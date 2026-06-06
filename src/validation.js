const stringType = {
  trim() {
    this.shouldTrim = true;
    return this;
  },
  min(value) {
    this.minLength = value;
    return this;
  },
  max(value) {
    this.maxLength = value;
    return this;
  },
  parse(value, key) {
    if (typeof value !== "string") {
      throw new ValidationError(`${key} must be a string`);
    }
    const parsed = this.shouldTrim ? value.trim() : value;
    if (this.minLength && parsed.length < this.minLength) {
      throw new ValidationError(`${key} is too short`);
    }
    if (this.maxLength && parsed.length > this.maxLength) {
      throw new ValidationError(`${key} is too long`);
    }
    return parsed;
  },
};

const booleanType = {
  refine(check, message) {
    this.check = check;
    this.message = message;
    return this;
  },
  parse(value, key) {
    if (typeof value !== "boolean") {
      throw new ValidationError(`${key} must be a boolean`);
    }
    if (this.check && !this.check(value)) {
      throw new ValidationError(this.message || `${key} is invalid`);
    }
    return value;
  },
};

class EnumType {
  constructor(values) {
    this.values = values;
  }

  parse(value, key) {
    if (!this.values.includes(value)) {
      throw new ValidationError(`${key} must be one of: ${this.values.join(", ")}`);
    }
    return value;
  }
}

class ObjectType {
  constructor(shape) {
    this.shape = shape;
  }

  parse(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError("Request body must be an object");
    }

    return Object.entries(this.shape).reduce((output, [key, parser]) => {
      output[key] = parser.parse(value[key], key);
      return output;
    }, {});
  }
}

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ZodError";
    this.errors = [{ message }];
  }
}

function cloneType(type) {
  return { ...type };
}

export const z = {
  string: () => cloneType(stringType),
  boolean: () => cloneType(booleanType),
  enum: (values) => new EnumType(values),
  object: (shape) => new ObjectType(shape),
};
