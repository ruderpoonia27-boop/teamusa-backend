import bcrypt from "bcryptjs";
import cors from "cors";
import "dotenv/config";
import express from "express";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import multer from "multer";
import morgan from "morgan";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { Readable } from "node:stream";
import Razorpay from "razorpay";
import Stripe from "stripe";

const app = express();
const port = Number(process.env.PORT || 4000);
const jwtSecret = process.env.JWT_SECRET || "dev-premium-secret";
const requireDatabase = process.env.REQUIRE_DATABASE === "true";
const uploadsRoot = path.join(process.cwd(), "uploads");
const thumbnailUploadDir = path.join(uploadsRoot, "thumbnails");
const videoUploadDir = path.join(uploadsRoot, "videos");
const paymentUploadDir = path.join(uploadsRoot, "payments");
const siteUploadDir = path.join(uploadsRoot, "site");
const publicDir = path.join(process.cwd(), "public");

fs.mkdirSync(thumbnailUploadDir, { recursive: true });
fs.mkdirSync(videoUploadDir, { recursive: true });
fs.mkdirSync(paymentUploadDir, { recursive: true });
fs.mkdirSync(siteUploadDir, { recursive: true });
fs.mkdirSync(publicDir, { recursive: true });

const defaultPremiumPlans = [
  { id: "days7", name: "7 Days", durationDays: 7, amount: 3900 },
  { id: "days15", name: "15 Days", durationDays: 15, amount: 6900 },
  { id: "month1", name: "1 Month", durationDays: 30, amount: 11900 },
];

const defaultPaymentSettings = {
  key: "premium",
  planName: "Premium Membership",
  priceAmount: 49900,
  originalAmount: 99900,
  offerLabel: "50% OFF",
  currency: "inr",
  upiId: "",
  paymentLink: "https://t.me/",
  paymentMessage: "I want to take premium membership. Plan: {plan} ({price}). My account email is {email}.",
  qrImageUrl: "",
  qrImagePath: "",
  heroImageUrl: "",
  heroImagePath: "",
  plans: defaultPremiumPlans,
};

const defaultCatalog = {
  categories: ["New", "Trending", "Popular"],
  sections: ["New", "Trending", "Popular"],
};

const upload = multer({
  storage: multer.diskStorage({
    destination(_request, file, callback) {
      if (file.fieldname === "thumbnail") {
        callback(null, thumbnailUploadDir);
        return;
      }
      if (file.fieldname === "upiQr") {
        callback(null, paymentUploadDir);
        return;
      }
      if (file.fieldname === "heroImage") {
        callback(null, siteUploadDir);
        return;
      }
      callback(null, videoUploadDir);
    },
    filename(_request, file, callback) {
      callback(null, `${Date.now()}-${cryptoId()}${path.extname(file.originalname || "")}`);
    },
  }),
  limits: {
    fileSize: 1024 * 1024 * 1024 * 3,
  },
  fileFilter(_request, file, callback) {
    if (["thumbnail", "upiQr", "heroImage"].includes(file.fieldname) && file.mimetype.startsWith("image/")) {
      callback(null, true);
      return;
    }
    if (["video", "videoHd", "videoSd"].includes(file.fieldname) && file.mimetype.startsWith("video/")) {
      callback(null, true);
      return;
    }
    callback(httpError(400, "Invalid upload file type."));
  },
});

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(
  cors({
    origin: resolveCorsOrigin,
  }),
);

app.post(
  "/api/payments/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (request, response) => {
    try {
      if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_WEBHOOK_SECRET) {
        response.status(400).json({ message: "Stripe webhook is not configured." });
        return;
      }

      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
      const signature = request.headers["stripe-signature"];
      const event = stripe.webhooks.constructEvent(
        request.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET,
      );

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const user = await findUserById(session.metadata?.userId);
        const plan = await getPlan(session.metadata?.plan);
        if (user) {
          await activatePremium(user, plan);
          await savePayment(user, plan, "stripe", "paid", session.id);
        }
      }

      response.json({ received: true });
    } catch (error) {
      response.status(400).json({ message: error.message });
    }
  },
);

app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));
app.use(
  "/assets",
  express.static(publicDir, {
    immutable: true,
    maxAge: "7d",
  }),
);
app.use(
  "/uploads/thumbnails",
  express.static(thumbnailUploadDir, {
    immutable: true,
    maxAge: "7d",
  }),
);
app.use(
  "/uploads/payments",
  express.static(paymentUploadDir, {
    maxAge: "1h",
  }),
);
app.use(
  "/uploads/site",
  express.static(siteUploadDir, {
    immutable: true,
    maxAge: "30d",
  }),
);

const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, default: "Member" },
    email: { type: String, unique: true, required: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    isBlocked: { type: Boolean, default: false },
    isPremium: { type: Boolean, default: false },
    plan: { type: String, default: "" },
    premiumSince: { type: Date },
    premiumUntil: { type: Date },
  },
  { timestamps: true },
);

const videoSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    creator: { type: String, trim: true, default: "TeamUSA" },
    category: { type: String, required: true, trim: true },
    section: { type: String, default: "Featured Videos", trim: true },
    thumbnailUrl: { type: String, default: "" },
    thumbnailPath: { type: String, default: "" },
    videoUrl: { type: String, default: "" },
    videoUrlHd: { type: String, default: "" },
    videoUrlSd: { type: String, default: "" },
    videoPath: { type: String, default: "" },
    videoPathHd: { type: String, default: "" },
    videoPathSd: { type: String, default: "" },
    duration: { type: String, default: "00:00" },
    views: { type: Number, default: 0 },
    premiumOnly: { type: Boolean, default: true },
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "approved" },
  },
  { timestamps: true },
);

const paymentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    plan: { type: String, required: true },
    provider: { type: String, enum: ["demo", "stripe", "razorpay"], default: "demo" },
    status: { type: String, enum: ["created", "paid", "failed"], default: "created" },
    providerReference: { type: String, default: "" },
    amount: { type: Number, required: true },
    currency: { type: String, default: "inr" },
  },
  { timestamps: true },
);

const paymentSettingsSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true, default: "premium" },
    planName: { type: String, trim: true, default: defaultPaymentSettings.planName },
    priceAmount: { type: Number, default: defaultPaymentSettings.priceAmount },
    originalAmount: { type: Number, default: defaultPaymentSettings.originalAmount },
    offerLabel: { type: String, trim: true, default: defaultPaymentSettings.offerLabel },
    currency: { type: String, default: "inr" },
    upiId: { type: String, trim: true, default: "" },
    paymentLink: { type: String, trim: true, default: defaultPaymentSettings.paymentLink },
    paymentMessage: { type: String, trim: true, default: defaultPaymentSettings.paymentMessage },
    qrImageUrl: { type: String, default: "" },
    qrImagePath: { type: String, default: "" },
    heroImageUrl: { type: String, default: "" },
    heroImagePath: { type: String, default: "" },
    plans: [
      {
        id: { type: String, required: true },
        name: { type: String, required: true },
        durationDays: { type: Number, required: true },
        amount: { type: Number, required: true },
      },
    ],
  },
  { timestamps: true },
);

const catalogItemSchema = new mongoose.Schema(
  {
    kind: { type: String, enum: ["category", "section"], required: true },
    name: { type: String, required: true, trim: true },
    slug: { type: String, required: true, trim: true },
    sortOrder: { type: Number, default: 0 },
  },
  { timestamps: true },
);

catalogItemSchema.index({ kind: 1, slug: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);
const Video = mongoose.model("Video", videoSchema);
const Payment = mongoose.model("Payment", paymentSchema);
const PaymentSettings = mongoose.model("PaymentSettings", paymentSettingsSchema);
const CatalogItem = mongoose.model("CatalogItem", catalogItemSchema);

const memory = {
  users: [],
  payments: [],
  videos: [],
  paymentSettings: { ...defaultPaymentSettings },
  catalogItems: buildDefaultCatalogItems(),
};

const demoVideos = [
  {
    id: "v1",
    title: "Midnight Studio Premiere",
    creator: "Luxe Originals",
    category: "New",
    section: "New",
    thumbnailUrl:
      "https://images.unsplash.com/photo-1492684223066-81342ee5ff30?auto=format&fit=crop&w=900&q=80",
    videoUrl:
      "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    duration: "18:42",
    views: 128000,
    premiumOnly: true,
  },
  {
    id: "v2",
    title: "Velvet Room Preview",
    creator: "Prime Channel",
    category: "Trending",
    section: "Trending",
    thumbnailUrl:
      "https://images.unsplash.com/photo-1516280440614-37939bbacd81?auto=format&fit=crop&w=900&q=80",
    videoUrl:
      "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    duration: "12:05",
    views: 84000,
    premiumOnly: true,
  },
];

app.get("/api/health", (_request, response) => {
  response.json({ ok: true, service: "luxevault-api" });
});

app.get("/api/videos", optionalAuth, async (request, response, next) => {
  try {
    const isPremium = isPremiumActive(request.user);

    if (!isDbReady()) {
      response.json({
        videos: memory.videos
          .filter((video) => video.status === "approved")
          .map((video) => serializeVideo(video, isPremium, request)),
      });
      return;
    }

    const videos = await Video.find({ status: "approved" })
      .sort({ createdAt: -1 })
      .limit(60)
      .lean();

    response.json({ videos: videos.map((video) => serializeVideo(video, isPremium, request)) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/catalog", async (_request, response, next) => {
  try {
    response.json({ catalog: await getCatalog() });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/videos", requireAdmin, async (request, response, next) => {
  try {
    if (!isDbReady()) {
      response.json({ videos: memory.videos.map((video) => serializeAdminVideo(video, request)) });
      return;
    }

    const videos = await Video.find().sort({ createdAt: -1 }).lean();
    response.json({ videos: videos.map((video) => serializeAdminVideo(video, request)) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/catalog", requireAdmin, async (_request, response, next) => {
  try {
    const items = await getCatalogItems();
    response.json({
      catalog: catalogFromItems(items),
      items: items.map(serializeCatalogItem),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/catalog", requireAdmin, async (request, response, next) => {
  try {
    await createCatalogItem(readCatalogItemInput(request.body));
    const items = await getCatalogItems();
    response.status(201).json({
      catalog: catalogFromItems(items),
      items: items.map(serializeCatalogItem),
    });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/catalog/:id", requireAdmin, async (request, response, next) => {
  try {
    await deleteCatalogItem(request.params.id);
    const items = await getCatalogItems();
    response.json({
      ok: true,
      catalog: catalogFromItems(items),
      items: items.map(serializeCatalogItem),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/videos/:id/playback-token", requirePremium, async (request, response, next) => {
  try {
    const video = await findVideoById(request.params.id);
    if (!video || video.status !== "approved") {
      throw httpError(404, "Video not found.");
    }

    const token = jwt.sign(
      {
        type: "playback",
        sub: String(request.user._id || request.user.id),
        videoId: String(video._id || video.id),
      },
      jwtSecret,
      { expiresIn: "2m" },
    );

    const baseUrl = `${request.protocol}://${request.get("host")}`;
    response.json({
      streamUrl: `${baseUrl}/api/videos/${video._id || video.id}/stream?token=${encodeURIComponent(token)}`,
      expiresInSeconds: 120,
      qualities: getAvailableQualities(video),
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/videos/:id/stream", async (request, response, next) => {
  try {
    const payload = jwt.verify(String(request.query.token || ""), jwtSecret);
    if (payload.type !== "playback" || payload.videoId !== request.params.id) {
      throw httpError(403, "Invalid playback token.");
    }

    const video = await findVideoById(request.params.id);
    if (!video || video.status !== "approved") {
      throw httpError(404, "Video not found.");
    }

    const source = selectVideoSource(video, request.query.quality);
    if (!source) throw httpError(404, "Video source missing.");

    if (source.type === "local") {
      streamLocalVideo(source.path, request, response);
      return;
    }

    const upstream = await fetch(source.url, {
      headers: request.headers.range ? { Range: request.headers.range } : {},
    });

    if (!upstream.ok && upstream.status !== 206) {
      throw httpError(502, "Video source unavailable.");
    }

    response.status(upstream.status);
    response.setHeader("Content-Type", upstream.headers.get("content-type") || "video/mp4");
    response.setHeader("Accept-Ranges", upstream.headers.get("accept-ranges") || "bytes");
    response.setHeader("Cache-Control", "no-store, private");
    response.setHeader("Content-Disposition", "inline");
    response.setHeader("X-Content-Type-Options", "nosniff");

    const contentLength = upstream.headers.get("content-length");
    const contentRange = upstream.headers.get("content-range");
    if (contentLength) response.setHeader("Content-Length", contentLength);
    if (contentRange) response.setHeader("Content-Range", contentRange);

    Readable.fromWeb(upstream.body).pipe(response);
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/videos", requireAdmin, upload.fields(getUploadFields()), async (request, response, next) => {
  try {
    const payload = readVideoInput(request.body);
    applyUploadedFiles(payload, request.files);
    validateVideoMedia(payload);

    if (!isDbReady()) {
      const video = {
        id: cryptoId(),
        views: 0,
        premiumOnly: true,
        status: "approved",
        ...payload,
      };
      memory.videos.unshift(video);
    response.status(201).json({ video: serializeAdminVideo(video, request) });
    return;
  }

  const video = await Video.create(payload);
  response.status(201).json({ video: serializeAdminVideo(video.toObject(), request) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/videos/:id", requireAdmin, upload.fields(getUploadFields()), async (request, response, next) => {
  try {
    const payload = readVideoInput(request.body, { partial: true });
    applyUploadedFiles(payload, request.files);

    if (!isDbReady()) {
      const index = memory.videos.findIndex((video) => video.id === request.params.id);
      if (index === -1) throw httpError(404, "Video not found.");
      memory.videos[index] = { ...memory.videos[index], ...payload };
      response.json({ video: serializeAdminVideo(memory.videos[index], request) });
      return;
    }

    const video = await Video.findByIdAndUpdate(request.params.id, payload, {
      new: true,
      runValidators: true,
    });
    if (!video) throw httpError(404, "Video not found.");
    response.json({ video: serializeAdminVideo(video.toObject(), request) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/videos/:id", requireAdmin, async (request, response, next) => {
  try {
    if (!isDbReady()) {
      const removedVideo = memory.videos.find((video) => video.id === request.params.id);
      const before = memory.videos.length;
      memory.videos = memory.videos.filter((video) => video.id !== request.params.id);
      if (memory.videos.length === before) throw httpError(404, "Video not found.");
      deleteUploadedFiles(removedVideo);
      response.json({ ok: true });
      return;
    }

    const video = await Video.findByIdAndDelete(request.params.id);
    if (!video) throw httpError(404, "Video not found.");
    deleteUploadedFiles(video);
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/users", requireAdmin, async (request, response, next) => {
  try {
    const search = String(request.query.search || "").trim();

    if (!isDbReady()) {
      memory.users.forEach(refreshExpiredSubscription);
      const users = memory.users
        .filter((user) => matchesUserSearch(user, search))
        .map(safePublicUser)
        .filter(Boolean)
        .slice(0, 100);
      response.json({ users });
      return;
    }

    const query = search
      ? {
          $or: [
            { name: { $regex: escapeRegex(search), $options: "i" } },
            { email: { $regex: escapeRegex(search), $options: "i" } },
          ],
        }
      : {};

    try {
      await expireDatabaseSubscriptions();
    } catch (error) {
      console.warn("Could not expire old subscriptions before listing users:", error.message);
    }
    let users = [];
    try {
      users = await User.find(query).sort({ createdAt: -1 }).limit(100).lean();
    } catch (error) {
      console.warn("Could not list users:", error.message);
    }
    response.json({ users: users.map(safePublicUser).filter(Boolean) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/users/:id/premium", requireAdmin, async (request, response, next) => {
  try {
    const isPremium = Boolean(request.body?.isPremium);
    const planId = String(request.body?.plan || request.body?.planId || "days15");
    const plan = isPremium ? await getPlan(planId) : null;

    if (!isDbReady()) {
      const user = memory.users.find((item) => item.id === request.params.id);
      if (!user) throw httpError(404, "User not found.");
      setPremiumState(user, isPremium, plan);
      response.json({ user: publicUser(user) });
      return;
    }

    const user = await User.findById(request.params.id);
    if (!user) throw httpError(404, "User not found.");
    setPremiumState(user, isPremium, plan);
    await user.save();
    response.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/users/:id/block", requireAdmin, async (request, response, next) => {
  try {
    const isBlocked = Boolean(request.body?.isBlocked);

    if (!isDbReady()) {
      const user = memory.users.find((item) => item.id === request.params.id);
      if (!user) throw httpError(404, "User not found.");
      if (user.role === "admin") throw httpError(400, "Admin account cannot be blocked.");
      user.isBlocked = isBlocked;
      response.json({ user: publicUser(user) });
      return;
    }

    const user = await User.findById(request.params.id);
    if (!user) throw httpError(404, "User not found.");
    if (user.role === "admin") throw httpError(400, "Admin account cannot be blocked.");
    user.isBlocked = isBlocked;
    await user.save();
    response.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/users/:id", requireAdmin, async (request, response, next) => {
  try {
    if (!isDbReady()) {
      const index = memory.users.findIndex((item) => item.id === request.params.id);
      if (index === -1) throw httpError(404, "User not found.");
      if (memory.users[index].role === "admin") throw httpError(400, "Admin account cannot be deleted.");
      memory.users.splice(index, 1);
      response.json({ ok: true });
      return;
    }

    const user = await User.findById(request.params.id);
    if (!user) throw httpError(404, "User not found.");
    if (user.role === "admin") throw httpError(400, "Admin account cannot be deleted.");
    await User.deleteOne({ _id: user._id });
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/payment-settings", async (request, response, next) => {
  try {
    const settings = await getPaymentSettings();
    response.json({ settings: serializePaymentSettings(settings, request) });
  } catch (error) {
    next(error);
  }
});

app.patch(
  "/api/admin/payment-settings",
  requireAdmin,
  upload.fields([
    { name: "upiQr", maxCount: 1 },
    { name: "heroImage", maxCount: 1 },
  ]),
  async (request, response, next) => {
    try {
      const payload = readPaymentSettingsInput(request.body);
      const upiQr = request.files?.upiQr?.[0];
      const heroImage = request.files?.heroImage?.[0];

      if (upiQr) {
        payload.qrImagePath = upiQr.filename;
        payload.qrImageUrl = `/uploads/payments/${upiQr.filename}`;
      }
      if (heroImage) {
        payload.heroImagePath = heroImage.filename;
        payload.heroImageUrl = `/uploads/site/${heroImage.filename}`;
      }

      if (!isDbReady()) {
        memory.paymentSettings = { ...memory.paymentSettings, ...payload };
        response.json({ settings: serializePaymentSettings(memory.paymentSettings, request) });
        return;
      }

      const settings = await PaymentSettings.findOneAndUpdate(
        { key: "premium" },
        { $set: { ...payload, key: "premium" } },
        { new: true, upsert: true, runValidators: true },
      ).lean();
      response.json({ settings: serializePaymentSettings(settings, request) });
    } catch (error) {
      next(error);
    }
  },
);

app.post("/api/auth/register", async (request, response, next) => {
  try {
    const { name, email, password } = readAuthInput(request.body);
    const passwordHash = await bcrypt.hash(password, 10);

    if (!isDbReady()) {
      if (memory.users.some((user) => user.email === email)) {
        response.status(409).json({ message: "Email already registered." });
        return;
      }

      const user = {
        id: cryptoId(),
        name,
        email,
        passwordHash,
        role: isAdminEmail(email) ? "admin" : "user",
        isBlocked: false,
        isPremium: false,
        plan: "",
      };
      memory.users.push(user);
      response.status(201).json(createSession(user));
      return;
    }

    const user = await User.create({
      name,
      email,
      passwordHash,
      role: isAdminEmail(email) ? "admin" : "user",
    });
    response.status(201).json(createSession(user));
  } catch (error) {
    if (error.code === 11000) {
      response.status(409).json({ message: "Email already registered." });
      return;
    }
    next(error);
  }
});

app.post("/api/auth/login", async (request, response, next) => {
  try {
    const { email, password } = readAuthInput(request.body, { requireName: false });
    const user = await findUserByEmail(email);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      response.status(401).json({ message: "Invalid email or password." });
      return;
    }
    if (user.isBlocked) {
      response.status(403).json({ message: "Your account is blocked." });
      return;
    }

    response.json(createSession(user));
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", requireAuth, (request, response) => {
  response.json(createSession(request.user));
});

app.post("/api/payments/create", requireAuth, async (request, response, next) => {
  try {
    const plan = await getPlan(request.body?.plan);
    const stripeSession = await createStripeSessionIfConfigured(plan, request.user);
    if (stripeSession) {
      await savePayment(request.user, plan, "stripe", "created", stripeSession.id);
      response.status(201).json({
        provider: "stripe",
        checkoutUrl: stripeSession.url,
        plan: plan.id,
        amount: plan.amount,
        currency: plan.currency,
        message: "Stripe checkout session created.",
      });
      return;
    }

    const razorpayOrder = await createRazorpayOrderIfConfigured(plan);
    if (razorpayOrder) {
      await savePayment(request.user, plan, "razorpay", "created", razorpayOrder.id);
      response.status(201).json({
        provider: "razorpay",
        order: razorpayOrder,
        plan: plan.id,
        amount: plan.amount,
        currency: plan.currency,
        message: "Razorpay order created.",
      });
      return;
    }

    const payment = await savePayment(request.user, plan, "demo", "created", cryptoId());
    response.status(201).json({
      provider: "demo",
      paymentId: payment.id || payment._id,
      plan: plan.id,
      amount: plan.amount,
      currency: plan.currency,
      message: "Demo payment created. Confirm it to activate premium.",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/payments/confirm-demo", requireAuth, async (request, response, next) => {
  try {
    const plan = await getPlan(request.body?.plan);
    const user = await activatePremium(request.user, plan);
    await savePayment(user, plan, "demo", "paid", cryptoId());
    response.json(createSession(user));
  } catch (error) {
    next(error);
  }
});

app.post("/api/payments/razorpay/verify", requireAuth, async (request, response, next) => {
  try {
    const {
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      plan: planId,
    } = request.body || {};

    if (!process.env.RAZORPAY_KEY_SECRET) {
      throw httpError(400, "Razorpay is not configured.");
    }

    const expected = createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest("hex");

    if (expected !== signature) {
      throw httpError(400, "Invalid Razorpay signature.");
    }

    const plan = await getPlan(planId);
    const user = await activatePremium(request.user, plan);
    await savePayment(user, plan, "razorpay", "paid", paymentId);
    response.json(createSession(user));
  } catch (error) {
    next(error);
  }
});

app.get("/api/dashboard", requireAuth, (request, response) => {
  response.json({
    user: publicUser(request.user),
    benefits: [
      "Unlock all videos",
      "Unlimited viewing",
      "HD streaming",
      "Faster loading",
      "Premium member badge",
      "Continue watching history",
      "Personalized dashboard",
    ],
  });
});

app.use((error, _request, response, _next) => {
  if (error.statusCode) {
    response.status(error.statusCode).json({ message: error.message });
    return;
  }

  console.error(error);
  response.status(500).json({ message: "Server error" });
});

async function start() {
  await ensureMemoryAdmin();
  memory.videos = demoVideos.map((video) => ({ status: "approved", ...video }));

  const uri = process.env.MONGODB_URI;
  if (uri) {
    try {
      await mongoose.connect(uri);
      await ensureDatabaseAdmin();
      await ensureDatabaseVideos();
      await ensurePaymentSettings();
      await ensureCatalogItems();
      console.log("MongoDB connected");
    } catch (error) {
      console.error(`MongoDB connection failed: ${error.message}`);
      if (requireDatabase) {
        process.exitCode = 1;
        return;
      }
      console.warn("Using in-memory demo data because REQUIRE_DATABASE is not true.");
    }
  } else if (requireDatabase) {
    console.error("MONGODB_URI is required when REQUIRE_DATABASE=true.");
    process.exitCode = 1;
    return;
  }

  listenWithFallback(port);
}

function readVideoInput(body, options = { partial: false }) {
  if (options.partial) {
    const payload = {};
    const stringFields = [
      "title",
      "creator",
      "category",
      "section",
      "thumbnailUrl",
      "thumbnailPath",
      "videoUrl",
      "videoUrlHd",
      "videoUrlSd",
      "videoPath",
      "videoPathHd",
      "videoPathSd",
      "duration",
      "status",
    ];

    for (const field of stringFields) {
      if (body?.[field] !== undefined) {
        payload[field] = String(body[field]).trim();
      }
    }
    if (body?.premiumOnly !== undefined) {
      payload.premiumOnly = Boolean(body.premiumOnly);
    }
    if (body?.views !== undefined) {
      payload.views = normalizeViews(body.views);
    }
    if (payload.status && !["pending", "approved", "rejected"].includes(payload.status)) {
      throw httpError(400, "Valid status is required.");
    }
    return payload;
  }

  const fields = {
    title: String(body?.title || "").trim(),
    creator: String(body?.creator || "TeamUSA").trim(),
    category: String(body?.category || "").trim(),
    section: String(body?.section || defaultCatalog.sections[0]).trim(),
    thumbnailUrl: String(body?.thumbnailUrl || "").trim(),
    thumbnailPath: String(body?.thumbnailPath || "").trim(),
    videoUrl: String(body?.videoUrl || "").trim(),
    videoUrlHd: String(body?.videoUrlHd || "").trim(),
    videoUrlSd: String(body?.videoUrlSd || "").trim(),
    videoPath: String(body?.videoPath || "").trim(),
    videoPathHd: String(body?.videoPathHd || "").trim(),
    videoPathSd: String(body?.videoPathSd || "").trim(),
    duration: String(body?.duration || "00:00").trim(),
    views: normalizeViews(body?.views),
    status: String(body?.status || "approved").trim(),
    premiumOnly: body?.premiumOnly === undefined ? true : Boolean(body.premiumOnly),
  };

  if (!fields.title) throw httpError(400, "Title is required.");
  if (!fields.creator) fields.creator = "TeamUSA";
  if (!fields.category) throw httpError(400, "Category is required.");
  if (!["pending", "approved", "rejected"].includes(fields.status)) {
    throw httpError(400, "Valid status is required.");
  }

  return fields;
}

function normalizeViews(value) {
  if (value === undefined || value === null || value === "") return 0;
  const views = Number(value);
  if (!Number.isFinite(views) || views < 0) throw httpError(400, "Valid views count is required.");
  return Math.round(views);
}

function readAuthInput(body, options = { requireName: true }) {
  const name = String(body?.name || "Member").trim();
  const email = String(body?.email || "").trim().toLowerCase();
  const password = String(body?.password || "");

  if (options.requireName && name.length < 2) {
    throw httpError(400, "Name is required.");
  }
  if (!email.includes("@")) {
    throw httpError(400, "Valid email is required.");
  }
  if (password.length < 6) {
    throw httpError(400, "Password must be at least 6 characters.");
  }

  return { name, email, password };
}

function readPaymentSettingsInput(body) {
  const payload = {};
  const planName = String(body?.planName || "").trim();
  const offerLabel = String(body?.offerLabel || "").trim();
  const upiId = String(body?.upiId || "").trim();
  const paymentLink = String(body?.paymentLink || "").trim();
  const paymentMessage = String(body?.paymentMessage || "").trim();
  const priceAmount = toPaise(body?.priceAmount);
  const originalAmount = toPaise(body?.originalAmount);
  const plans = readPremiumPlansInput(body?.plans);

  if (planName) payload.planName = planName;
  if (offerLabel || body?.offerLabel === "") payload.offerLabel = offerLabel;
  if (upiId || body?.upiId === "") payload.upiId = upiId;
  if (paymentLink || body?.paymentLink === "") payload.paymentLink = paymentLink;
  if (paymentMessage || body?.paymentMessage === "") {
    payload.paymentMessage = paymentMessage || defaultPaymentSettings.paymentMessage;
  }
  if (priceAmount !== null) payload.priceAmount = priceAmount;
  if (originalAmount !== null) payload.originalAmount = originalAmount;
  if (priceAmount !== null && originalAmount !== null) {
    payload.offerLabel = calculateOfferLabel(priceAmount, originalAmount);
  }
  if (plans) payload.plans = plans;
  if (body?.clearQr === "true" || body?.clearQr === true) {
    payload.qrImageUrl = "";
    payload.qrImagePath = "";
  }
  if (body?.clearHero === "true" || body?.clearHero === true) {
    payload.heroImageUrl = "";
    payload.heroImagePath = "";
  }
  payload.currency = "inr";

  if (payload.priceAmount !== undefined && payload.priceAmount < 100) {
    throw httpError(400, "Price must be at least INR 1.");
  }
  if (
    payload.originalAmount !== undefined &&
    payload.priceAmount !== undefined &&
    payload.originalAmount < payload.priceAmount
  ) {
    throw httpError(400, "Original price cannot be lower than current price.");
  }

  return payload;
}

function readCatalogItemInput(body) {
  const kind = String(body?.kind || "").trim().toLowerCase();
  const name = String(body?.name || "").trim().replace(/\s+/g, " ");
  const slug = catalogSlug(name);

  if (!["category", "section"].includes(kind)) {
    throw httpError(400, "Valid catalog type is required.");
  }
  if (name.length < 2) {
    throw httpError(400, "Name must be at least 2 characters.");
  }
  if (name.length > 40) {
    throw httpError(400, "Name cannot be longer than 40 characters.");
  }
  if (!slug) {
    throw httpError(400, "Name must contain letters or numbers.");
  }

  return { kind, name, slug };
}

async function createCatalogItem(payload) {
  if (!isDbReady()) {
    const exists = memory.catalogItems.some(
      (item) => item.kind === payload.kind && item.slug === payload.slug,
    );
    if (exists) throw httpError(409, "This item already exists.");

    const item = {
      id: cryptoId(),
      ...payload,
      sortOrder: nextCatalogSortOrder(memory.catalogItems, payload.kind),
    };
    memory.catalogItems.push(item);
    return item;
  }

  const exists = await CatalogItem.findOne({ kind: payload.kind, slug: payload.slug }).lean();
  if (exists) throw httpError(409, "This item already exists.");

  return CatalogItem.create({
    ...payload,
    sortOrder: await nextDatabaseCatalogSortOrder(payload.kind),
  });
}

async function deleteCatalogItem(id) {
  if (!id) throw httpError(400, "Catalog item is required.");

  if (!isDbReady()) {
    const item = memory.catalogItems.find((entry) => entry.id === id);
    if (!item) throw httpError(404, "Catalog item not found.");
    if (isDefaultCatalogItem(item)) throw httpError(400, "Default category cannot be deleted.");

    const remaining = memory.catalogItems.filter(
      (entry) => entry.kind === item.kind && entry.id !== id,
    );
    if (!remaining.length) throw httpError(400, "At least one item is required.");

    const fallback = remaining.sort(sortCatalogItems)[0];
    reassignCatalogVideos(item, fallback.name);
    memory.catalogItems = memory.catalogItems.filter((entry) => entry.id !== id);
    return;
  }

  const item = await CatalogItem.findById(id).lean();
  if (!item) throw httpError(404, "Catalog item not found.");
  if (isDefaultCatalogItem(item)) throw httpError(400, "Default category cannot be deleted.");

  const remaining = await CatalogItem.find({ kind: item.kind, _id: { $ne: item._id } })
    .sort({ sortOrder: 1, name: 1 })
    .lean();
  if (!remaining.length) throw httpError(400, "At least one item is required.");

  const fallback = remaining[0];
  await reassignDatabaseCatalogVideos(item, fallback.name);
  await CatalogItem.findByIdAndDelete(id);
}

function buildDefaultCatalogItems() {
  return buildDefaultCatalogEntries().map((entry) => ({
    id: cryptoId(),
    ...entry,
  }));
}

function buildDefaultCatalogEntries() {
  return [
    ...defaultCatalog.categories.map((name, index) => ({
      kind: "category",
      name,
      slug: catalogSlug(name),
      sortOrder: index,
    })),
    ...defaultCatalog.sections.map((name, index) => ({
      kind: "section",
      name,
      slug: catalogSlug(name),
      sortOrder: index,
    })),
  ];
}

function isDefaultCatalogItem(item) {
  if (!item) return false;
  const list = item.kind === "section" ? defaultCatalog.sections : defaultCatalog.categories;
  return list.map(catalogSlug).includes(item.slug || catalogSlug(item.name));
}

function catalogSlug(name) {
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function nextCatalogSortOrder(items, kind) {
  return (
    items
      .filter((item) => item.kind === kind)
      .reduce((highest, item) => Math.max(highest, Number(item.sortOrder) || 0), -1) + 1
  );
}

async function nextDatabaseCatalogSortOrder(kind) {
  const latest = await CatalogItem.findOne({ kind }).sort({ sortOrder: -1 }).lean();
  return (Number(latest?.sortOrder) || 0) + 1;
}

function sortCatalogItems(first, second) {
  return (first.sortOrder || 0) - (second.sortOrder || 0) || first.name.localeCompare(second.name);
}

function reassignCatalogVideos(item, fallbackName) {
  const field = item.kind === "category" ? "category" : "section";
  memory.videos = memory.videos.map((video) =>
    video[field] === item.name ? { ...video, [field]: fallbackName } : video,
  );
}

async function reassignDatabaseCatalogVideos(item, fallbackName) {
  const field = item.kind === "category" ? "category" : "section";
  await Video.updateMany({ [field]: item.name }, { $set: { [field]: fallbackName } });
}

function toPaise(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  if (!Number.isFinite(number)) throw httpError(400, "Valid INR amount is required.");
  return Math.round(number * 100);
}

function readPremiumPlansInput(value) {
  if (value === undefined || value === null || value === "") return null;

  let parsed;
  try {
    parsed = typeof value === "string" ? JSON.parse(value) : value;
  } catch {
    throw httpError(400, "Valid premium plans are required.");
  }

  if (!Array.isArray(parsed)) throw httpError(400, "Valid premium plans are required.");

  return defaultPremiumPlans.map((defaultPlan) => {
    const item = parsed.find((plan) => plan?.id === defaultPlan.id) || {};
    const durationDays = Number(item.durationDays);
    const amount = toPaise(item.amount);

    if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 365) {
      throw httpError(400, "Plan days must be between 1 and 365.");
    }
    if (amount === null || amount < 100) {
      throw httpError(400, "Plan amount must be at least INR 1.");
    }

    return {
      id: defaultPlan.id,
      name: formatPlanName(defaultPlan.id, durationDays),
      durationDays,
      amount,
    };
  });
}

function calculateOfferLabel(priceAmount = 0, originalAmount = 0) {
  if (!Number.isFinite(priceAmount) || !Number.isFinite(originalAmount) || priceAmount <= 0 || originalAmount <= priceAmount) {
    return "";
  }

  const percentage = Math.round(((originalAmount - priceAmount) / originalAmount) * 100);
  return percentage > 0 ? `${percentage}% OFF` : "";
}

async function findUserByEmail(email) {
  if (!isDbReady()) {
    return memory.users.find((user) => user.email === email);
  }
  return User.findOne({ email });
}

async function findUserById(id) {
  if (!id) return null;
  if (!isDbReady()) {
    return memory.users.find((user) => user.id === id) || null;
  }
  return User.findById(id);
}

function matchesUserSearch(user, search) {
  if (!search) return true;
  const value = `${user.name || ""} ${user.email || ""}`.toLowerCase();
  return value.includes(search.toLowerCase());
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function setPremiumState(user, isPremium, plan = null) {
  if (!isPremium) {
    user.isPremium = false;
    user.plan = "";
    user.premiumSince = null;
    user.premiumUntil = null;
    return;
  }

  const selectedPlan = plan || getPremiumPlan("days15");
  const now = new Date();
  user.isPremium = true;
  user.plan = selectedPlan.id;
  user.premiumSince = now;
  user.premiumUntil = addDays(now, selectedPlan.durationDays);
}

function isPremiumActive(user) {
  if (!user) return false;
  if (user.isBlocked) return false;
  if (user.role === "admin") return true;
  if (!user.isPremium) return false;
  if (!user.premiumUntil) return true;
  return new Date(user.premiumUntil).getTime() > Date.now();
}

async function refreshExpiredSubscription(user) {
  if (!user || user.role === "admin" || !user.isPremium || !user.premiumUntil) return user;
  if (new Date(user.premiumUntil).getTime() > Date.now()) return user;

  user.isPremium = false;
  user.plan = "";
  user.premiumSince = null;
  user.premiumUntil = null;
  if (typeof user.save === "function") await user.save();
  return user;
}

async function expireDatabaseSubscriptions() {
  if (!isDbReady()) return;
  await User.updateMany(
    {
      role: { $ne: "admin" },
      isPremium: true,
      premiumUntil: { $lte: new Date() },
    },
    {
      $set: { isPremium: false, plan: "" },
      $unset: { premiumSince: "", premiumUntil: "" },
    },
  );
}

function getPremiumPlan(planId = "days15", options = {}) {
  const plan = defaultPremiumPlans.find((item) => item.id === planId);
  if (plan) return plan;
  if (options.fallback === null) return null;
  throw httpError(400, "Valid subscription plan is required.");
}

function getConfiguredPlans(settings = defaultPaymentSettings) {
  const source = Array.isArray(settings?.plans) && settings.plans.length ? settings.plans : defaultPremiumPlans;

  return defaultPremiumPlans.map((defaultPlan) => {
    const item = source.find((plan) => plan?.id === defaultPlan.id) || defaultPlan;
    const durationDays = Number(item.durationDays) || defaultPlan.durationDays;
    const amount = Number(item.amount) || defaultPlan.amount;

    return {
      id: defaultPlan.id,
      name: formatPlanName(defaultPlan.id, durationDays),
      durationDays,
      amount,
    };
  });
}

function formatPlanName(planId, durationDays) {
  if (planId === "month1" && durationDays === 30) return "1 Month";
  return `${durationDays} Days`;
}

function addDays(date, days) {
  const nextDate = new Date(date);
  nextDate.setDate(nextDate.getDate() + days);
  return nextDate;
}

function getSubscriptionDays(user) {
  if (!user?.premiumSince || !user?.premiumUntil) return 0;
  const start = new Date(user.premiumSince).getTime();
  const end = new Date(user.premiumUntil).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 0;
  return Math.round((end - start) / (1000 * 60 * 60 * 24));
}

function getRemainingSubscriptionDays(user) {
  if (!user?.premiumUntil || !isPremiumActive(user)) return 0;
  const end = new Date(user.premiumUntil).getTime();
  if (!Number.isFinite(end)) return 0;
  return Math.max(0, Math.ceil((end - Date.now()) / (1000 * 60 * 60 * 24)));
}

async function findVideoById(id) {
  if (!id) return null;
  if (!isDbReady()) {
    return memory.videos.find((video) => video.id === id) || null;
  }
  return Video.findById(id).lean();
}

async function requireAuth(request, response, next) {
  try {
    const user = await readUserFromToken(request);
    if (!user) {
      response.status(401).json({ message: "Authentication required." });
      return;
    }
    if (user.isBlocked) {
      response.status(403).json({ message: "Your account is blocked." });
      return;
    }
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function requireAdmin(request, response, next) {
  try {
    const user = await readUserFromToken(request);
    if (!user) {
      response.status(401).json({ message: "Authentication required." });
      return;
    }
    if (user.isBlocked) {
      response.status(403).json({ message: "Your account is blocked." });
      return;
    }
    if (user.role !== "admin") {
      response.status(403).json({ message: "Admin access required." });
      return;
    }
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function requirePremium(request, response, next) {
  try {
    const user = await readUserFromToken(request);
    if (!user) {
      response.status(401).json({ message: "Authentication required." });
      return;
    }
    if (user.isBlocked) {
      response.status(403).json({ message: "Your account is blocked." });
      return;
    }
    if (!isPremiumActive(user)) {
      response.status(402).json({ message: "Premium membership required." });
      return;
    }
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function optionalAuth(request, _response, next) {
  try {
    request.user = await readUserFromToken(request);
    next();
  } catch {
    next();
  }
}

async function readUserFromToken(request) {
  const header = request.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;

  let payload;
  try {
    payload = jwt.verify(token, jwtSecret);
  } catch {
    return null;
  }
  if (!payload?.sub) return null;

  if (!isDbReady()) {
    const user = memory.users.find((item) => item.id === payload.sub) || null;
    if (user) refreshExpiredSubscription(user);
    return user;
  }

  if (!mongoose.isValidObjectId(payload.sub)) return null;

  try {
    const user = await User.findById(payload.sub);
    if (user) await refreshExpiredSubscription(user);
    return user;
  } catch {
    return null;
  }
}

function createSession(user) {
  const cleanUser = publicUser(user);
  const token = jwt.sign(
    { sub: cleanUser.id, role: cleanUser.role, isPremium: cleanUser.isPremium },
    jwtSecret,
    { expiresIn: "7d" },
  );

  return { token, user: cleanUser };
}

function publicUser(user) {
  const activePlan = getPremiumPlan(user.plan, { fallback: null });
  const subscriptionDays = getSubscriptionDays(user);
  const remainingDays = getRemainingSubscriptionDays(user);
  const premiumActive = isPremiumActive(user);
  const planName = getPublicPlanName(user, activePlan, subscriptionDays);
  return {
    id: String(user._id || user.id),
    name: user.name,
    email: user.email,
    role: user.role || "user",
    isBlocked: Boolean(user.isBlocked),
    isPremium: premiumActive,
    plan: user.plan || "",
    planName,
    premiumSince: user.premiumSince || null,
    premiumUntil: user.premiumUntil || null,
    subscriptionDays,
    remainingDays,
  };
}

function safePublicUser(user) {
  try {
    return publicUser(user);
  } catch (error) {
    console.warn("Could not serialize user:", error.message);
    if (!user) return null;
    return {
      id: String(user._id || user.id || ""),
      name: user.name || "Member",
      email: user.email || "",
      role: user.role || "user",
      isBlocked: Boolean(user.isBlocked),
      isPremium: false,
      plan: user.plan || "",
      planName: "",
      premiumSince: user.premiumSince || null,
      premiumUntil: user.premiumUntil || null,
      subscriptionDays: 0,
      remainingDays: 0,
    };
  }
}

function getPublicPlanName(user, activePlan, subscriptionDays) {
  if (user.role === "admin") return "Admin Access";
  if (!isPremiumActive(user)) return "";
  if (activePlan) return formatPlanName(user.plan, subscriptionDays || activePlan.durationDays);
  if (subscriptionDays) return formatPlanName(user.plan, subscriptionDays);
  return "Premium";
}

async function ensureMemoryAdmin() {
  const email = getAdminEmail();
  const existing = memory.users.find((user) => user.email === email);
  if (existing) {
    existing.name = "Admin";
    existing.passwordHash = await bcrypt.hash(getAdminPassword(), 10);
    existing.role = "admin";
    existing.isPremium = true;
    existing.plan = "lifetime";
    existing.premiumSince = existing.premiumSince || new Date().toISOString();
    return;
  }

  memory.users.push({
    id: "admin-dev",
    name: "Admin",
    email,
    passwordHash: await bcrypt.hash(getAdminPassword(), 10),
    role: "admin",
    isPremium: true,
    plan: "lifetime",
    premiumSince: new Date().toISOString(),
  });
}

async function ensureDatabaseAdmin() {
  const email = getAdminEmail();
  const existing = await User.findOne({ email });
  if (existing) {
    existing.name = "Admin";
    existing.passwordHash = await bcrypt.hash(getAdminPassword(), 10);
    existing.role = "admin";
    existing.isPremium = true;
    existing.plan = "lifetime";
    existing.premiumSince = existing.premiumSince || new Date();
    await existing.save();
    return;
  }

  await User.create({
    name: "Admin",
    email,
    passwordHash: await bcrypt.hash(getAdminPassword(), 10),
    role: "admin",
    isPremium: true,
    plan: "lifetime",
    premiumSince: new Date(),
  });
}

async function ensureDatabaseVideos() {
  const count = await Video.countDocuments();
  if (count > 0) return;
  await Video.insertMany(demoVideos);
}

async function ensurePaymentSettings() {
  const existing = await PaymentSettings.findOne({ key: "premium" });
  if (existing) return;
  await PaymentSettings.create(defaultPaymentSettings);
}

async function ensureCatalogItems() {
  const entries = buildDefaultCatalogEntries();

  await Video.updateMany(
    { $or: [{ category: { $exists: false } }, { category: "" }] },
    { $set: { category: defaultCatalog.categories[0] } },
  );
  await Video.updateMany(
    { section: { $nin: defaultCatalog.sections } },
    { $set: { section: defaultCatalog.sections[0] } },
  );

  for (const entry of entries) {
    await CatalogItem.updateOne(
      { kind: entry.kind, slug: entry.slug },
      { $setOnInsert: entry },
      { upsert: true },
    );
  }
}

function isAdminEmail(email) {
  return email === getAdminEmail();
}

function getAdminEmail() {
  return (process.env.ADMIN_EMAIL || "admin@luxevault.local").trim().toLowerCase();
}

function getAdminPassword() {
  return process.env.ADMIN_PASSWORD || "admin123";
}

function serializeVideo(video, isPremium, request) {
  return {
    id: String(video._id || video.id),
    title: video.title,
    creator: video.creator || "TeamUSA",
    category: video.category,
    section: video.section,
    thumbnailUrl: getThumbnailUrl(video, request),
    duration: isPremium || video.premiumOnly === false ? video.duration : "",
    views: video.views,
    premiumOnly: video.premiumOnly,
    status: video.status,
    locked: Boolean(video.premiumOnly && !isPremium),
    hasPlayback: Boolean(
      isPremium &&
        (video.videoPath ||
          video.videoPathHd ||
          video.videoPathSd ||
          video.videoUrl ||
          video.videoUrlHd ||
          video.videoUrlSd),
    ),
  };
}

function serializeAdminVideo(video, request) {
  return {
    ...video,
    id: String(video._id || video.id),
    thumbnailUrl: getThumbnailUrl(video, request),
    sourceType: video.videoPath || video.videoPathHd || video.videoPathSd ? "Uploaded file" : "External URL",
  };
}

async function getPaymentSettings() {
  if (!isDbReady()) return memory.paymentSettings;
  return (await PaymentSettings.findOne({ key: "premium" }).lean()) || defaultPaymentSettings;
}

async function getCatalog() {
  return catalogFromItems(await getCatalogItems());
}

async function getCatalogItems() {
  if (!isDbReady()) {
    return [...memory.catalogItems].sort(sortCatalogItems);
  }
  try {
    const items = await CatalogItem.find().sort({ kind: 1, sortOrder: 1, name: 1 }).lean();
    return items.length ? items : buildDefaultCatalogItems();
  } catch (error) {
    console.warn("Could not load catalog items:", error.message);
    return buildDefaultCatalogItems();
  }
}

function catalogFromItems(items) {
  const categories = items
    .filter((item) => item.kind === "category")
    .sort((first, second) => sortByCatalogOrder(first, second, defaultCatalog.categories))
    .map((item) => item.name);
  const sections = items
    .filter((item) => item.kind === "section")
    .sort((first, second) => sortByCatalogOrder(first, second, defaultCatalog.sections))
    .map((item) => item.name);

  return {
    categories: categories.length ? categories : [...defaultCatalog.categories],
    sections: sections.length ? sections : [...defaultCatalog.sections],
  };
}

function sortByCatalogOrder(first, second, order) {
  const firstIndex = order.indexOf(first.name);
  const secondIndex = order.indexOf(second.name);
  const normalizedFirst = firstIndex === -1 ? Number.MAX_SAFE_INTEGER : firstIndex;
  const normalizedSecond = secondIndex === -1 ? Number.MAX_SAFE_INTEGER : secondIndex;
  return normalizedFirst - normalizedSecond || first.name.localeCompare(second.name);
}

function serializeCatalogItem(item) {
  return {
    id: String(item._id || item.id),
    kind: item.kind,
    name: item.name,
    slug: item.slug,
    sortOrder: item.sortOrder || 0,
  };
}

function serializePaymentSettings(settings, request) {
  const normalized = { ...defaultPaymentSettings, ...settings };
  return {
    planId: "premium",
    planName: normalized.planName,
    priceAmount: normalized.priceAmount,
    originalAmount: normalized.originalAmount,
    offerLabel: calculateOfferLabel(normalized.priceAmount, normalized.originalAmount) || normalized.offerLabel,
    currency: "inr",
    priceText: formatInr(normalized.priceAmount),
    originalPriceText: formatInr(normalized.originalAmount),
    plans: getConfiguredPlans(normalized).map(serializePremiumPlan),
    upiId: normalized.upiId,
    paymentLink: normalized.paymentLink || "",
    paymentMessage: normalized.paymentMessage || defaultPaymentSettings.paymentMessage,
    qrImageUrl: getPaymentQrUrl(normalized, request),
    heroImageUrl: getHeroImageUrl(normalized, request),
  };
}

function serializePremiumPlan(plan) {
  return {
    id: plan.id,
    name: plan.name,
    durationDays: plan.durationDays,
    amount: plan.amount,
    priceText: formatInr(plan.amount),
  };
}

function getPaymentQrUrl(settings, request) {
  if (settings.qrImageUrl?.startsWith("http")) return settings.qrImageUrl;
  if (settings.qrImageUrl?.startsWith("/uploads/")) {
    return `${request.protocol}://${request.get("host")}${settings.qrImageUrl}`;
  }
  if (settings.qrImagePath) {
    return `${request.protocol}://${request.get("host")}/uploads/payments/${settings.qrImagePath}`;
  }
  return "";
}

function getHeroImageUrl(settings, request) {
  if (settings.heroImageUrl?.startsWith("http")) return settings.heroImageUrl;
  if (settings.heroImageUrl?.startsWith("/uploads/")) {
    return `${request.protocol}://${request.get("host")}${settings.heroImageUrl}`;
  }
  if (settings.heroImagePath) {
    return `${request.protocol}://${request.get("host")}/uploads/site/${settings.heroImagePath}`;
  }
  return "";
}

function formatInr(amount = 0) {
  return `INR ${(amount / 100).toLocaleString("en-IN", {
    maximumFractionDigits: 0,
  })}`;
}

function getAvailableQualities(video) {
  const qualities = [{ id: "auto", label: "Auto" }];
  if (video.videoPathHd || video.videoUrlHd || video.videoPath || video.videoUrl) {
    qualities.push({ id: "hd", label: "HD" });
  }
  if (video.videoPathSd || video.videoUrlSd || video.videoPath || video.videoUrl) {
    qualities.push({ id: "sd", label: "SD" });
  }
  return qualities;
}

function selectVideoSource(video, quality) {
  const localPath =
    quality === "sd"
      ? video.videoPathSd || video.videoPath
      : quality === "hd"
        ? video.videoPathHd || video.videoPath
        : video.videoPathHd || video.videoPath || video.videoPathSd;

  if (localPath) {
    return { type: "local", path: getSafeUploadPath(localPath, videoUploadDir) };
  }

  const url =
    quality === "sd"
      ? video.videoUrlSd || video.videoUrl
      : quality === "hd"
        ? video.videoUrlHd || video.videoUrl
        : video.videoUrlHd || video.videoUrl || video.videoUrlSd;

  return url ? { type: "remote", url } : null;
}

function getUploadFields() {
  return [
    { name: "thumbnail", maxCount: 1 },
    { name: "video", maxCount: 1 },
    { name: "videoHd", maxCount: 1 },
    { name: "videoSd", maxCount: 1 },
  ];
}

function applyUploadedFiles(payload, files = {}) {
  const thumbnail = files.thumbnail?.[0];
  const video = files.video?.[0];
  const videoHd = files.videoHd?.[0];
  const videoSd = files.videoSd?.[0];

  if (thumbnail) {
    payload.thumbnailPath = thumbnail.filename;
    payload.thumbnailUrl = `/uploads/thumbnails/${thumbnail.filename}`;
  }
  if (video) payload.videoPath = video.filename;
  if (videoHd) payload.videoPathHd = videoHd.filename;
  if (videoSd) payload.videoPathSd = videoSd.filename;
}

function validateVideoMedia(payload) {
  if (
    !payload.videoUrl &&
    !payload.videoUrlHd &&
    !payload.videoUrlSd &&
    !payload.videoPath &&
    !payload.videoPathHd &&
    !payload.videoPathSd
  ) {
    throw httpError(400, "Video file is required.");
  }
}

function getThumbnailUrl(video, request) {
  if (video.thumbnailUrl?.startsWith("http")) return video.thumbnailUrl;
  if (video.thumbnailUrl?.startsWith("/uploads/")) {
    return `${request.protocol}://${request.get("host")}${video.thumbnailUrl}`;
  }
  if (video.thumbnailPath) {
    return `${request.protocol}://${request.get("host")}/uploads/thumbnails/${video.thumbnailPath}`;
  }
  return `${request.protocol}://${request.get("host")}/assets/default-thumbnail.svg`;
}

function getSafeUploadPath(filename, root) {
  const resolved = path.resolve(root, filename);
  const rootResolved = path.resolve(root);
  if (!resolved.startsWith(rootResolved)) {
    throw httpError(400, "Invalid media path.");
  }
  return resolved;
}

function streamLocalVideo(filePath, request, response) {
  if (!fs.existsSync(filePath)) {
    throw httpError(404, "Video file not found.");
  }

  const stat = fs.statSync(filePath);
  const fileSize = stat.size;
  const range = request.headers.range;

  response.setHeader("Content-Type", getVideoContentType(filePath));
  response.setHeader("Accept-Ranges", "bytes");
  response.setHeader("Cache-Control", "no-store, private");
  response.setHeader("Content-Disposition", "inline");
  response.setHeader("X-Content-Type-Options", "nosniff");

  if (!range) {
    response.setHeader("Content-Length", fileSize);
    fs.createReadStream(filePath).pipe(response);
    return;
  }

  const [startText, endText] = range.replace(/bytes=/, "").split("-");
  const start = Number.parseInt(startText, 10);
  const end = endText ? Number.parseInt(endText, 10) : fileSize - 1;

  if (Number.isNaN(start) || Number.isNaN(end) || start >= fileSize || end >= fileSize) {
    response.status(416).setHeader("Content-Range", `bytes */${fileSize}`);
    response.end();
    return;
  }

  response.status(206);
  response.setHeader("Content-Range", `bytes ${start}-${end}/${fileSize}`);
  response.setHeader("Content-Length", end - start + 1);
  fs.createReadStream(filePath, { start, end }).pipe(response);
}

function getVideoContentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === ".webm") return "video/webm";
  if (extension === ".ogg" || extension === ".ogv") return "video/ogg";
  if (extension === ".mov") return "video/quicktime";
  return "video/mp4";
}

function deleteUploadedFiles(video) {
  if (!video) return;

  const files = [
    [video.thumbnailPath, thumbnailUploadDir],
    [video.videoPath, videoUploadDir],
    [video.videoPathHd, videoUploadDir],
    [video.videoPathSd, videoUploadDir],
  ];

  for (const [filename, root] of files) {
    if (!filename) continue;
    try {
      const filePath = getSafeUploadPath(filename, root);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    } catch {
      // Ignore cleanup errors; the database delete should not fail because a file is missing.
    }
  }
}

async function activatePremium(user, plan) {
  if (!isDbReady()) {
    user.isPremium = true;
    user.plan = plan.id;
    user.premiumSince = new Date().toISOString();
    user.premiumUntil = addDays(new Date(), plan.durationDays).toISOString();
    return user;
  }

  user.isPremium = true;
  user.plan = plan.id;
  user.premiumSince = new Date();
  user.premiumUntil = addDays(new Date(), plan.durationDays);
  await user.save();
  return user;
}

async function savePayment(user, plan, provider, status, providerReference) {
  const payload = {
    userId: user._id,
    plan: plan.id,
    provider,
    status,
    providerReference,
    amount: plan.amount,
    currency: plan.currency,
  };

  if (!isDbReady()) {
    const payment = { id: cryptoId(), ...payload };
    memory.payments.push(payment);
    return payment;
  }

  return Payment.create(payload);
}

async function createStripeSessionIfConfigured(plan, user) {
  if (!process.env.STRIPE_SECRET_KEY) return null;

  const price =
    process.env.STRIPE_PREMIUM_PRICE_ID ||
    process.env.STRIPE_MONTHLY_PRICE_ID ||
    process.env.STRIPE_LIFETIME_PRICE_ID;
  if (!price) return null;

  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  return stripe.checkout.sessions.create({
    mode: plan.id === "monthly" ? "subscription" : "payment",
    customer_email: user.email,
    line_items: [{ price, quantity: 1 }],
    success_url: `${process.env.CORS_ORIGIN || "http://localhost:5173"}?payment=success`,
    cancel_url: `${process.env.CORS_ORIGIN || "http://localhost:5173"}?payment=cancelled`,
    metadata: {
      userId: String(user._id || user.id),
      plan: plan.id,
    },
  });
}

async function createRazorpayOrderIfConfigured(plan) {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) return null;

  const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });

  return razorpay.orders.create({
    amount: plan.razorpayAmount,
    currency: "INR",
    receipt: cryptoId(),
    notes: { plan: plan.id },
  });
}

async function getPlan(planId = "premium") {
  const selectedPlanId = planId === "premium" ? "days15" : planId;
  const settings = await getPaymentSettings();
  const plan = getConfiguredPlans(settings).find((item) => item.id === (selectedPlanId || "days15"));
  if (!plan) throw httpError(400, "Valid subscription plan is required.");
  return {
    id: plan.id,
    name: plan.name,
    durationDays: plan.durationDays,
    amount: plan.amount,
    currency: "inr",
    razorpayAmount: plan.amount,
  };
}

function isDbReady() {
  return mongoose.connection.readyState === 1;
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function cryptoId() {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
}

function resolveCorsOrigin(origin, callback) {
  if (!origin) {
    callback(null, true);
    return;
  }

  const configuredOrigins = (process.env.CORS_ORIGIN || "*")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  if (configuredOrigins.includes("*") || configuredOrigins.includes(origin)) {
    callback(null, true);
    return;
  }

  const isLocalDevOrigin =
    /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]):5173$/.test(origin) ||
    /^https?:\/\/10\.\d+\.\d+\.\d+:5173$/.test(origin) ||
    /^https?:\/\/192\.168\.\d+\.\d+:5173$/.test(origin) ||
    /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+:5173$/.test(origin);

  callback(null, isLocalDevOrigin);
}

function listenWithFallback(startPort, attemptsLeft = 10) {
  const server = http.createServer(app);

  server.on("error", (error) => {
    if (error.code === "EADDRINUSE" && attemptsLeft > 0) {
      const nextPort = startPort + 1;
      console.warn(`Port ${startPort} busy, trying ${nextPort}...`);
      listenWithFallback(nextPort, attemptsLeft - 1);
      return;
    }

    console.error(error);
    process.exitCode = 1;
  });

  server.listen(startPort, () => {
    console.log(`LuxeVault API running on http://localhost:${startPort}`);
  });
}

start();
