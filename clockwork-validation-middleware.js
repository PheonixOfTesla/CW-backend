const Joi = require('joi');

// Validation middleware factory
const validateRequest = (schema, property = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errors = error.details.reduce((acc, detail) => {
        const key = detail.path.join('.');
        acc[key] = detail.message;
        return acc;
      }, {});

      return res.status(400).json({
        error: 'Validation failed',
        details: errors
      });
    }

    // Replace request property with validated value
    req[property] = value;
    next();
  };
};

// Common validation schemas
const schemas = {
  // UUID validation
  uuid: Joi.string().uuid({ version: 'uuidv4' }),
  
  // Email validation
  email: Joi.string().email().lowercase().trim(),
  
  // Password validation
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .message('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  // Phone validation
  phone: Joi.string().pattern(/^\+?[\d\s-()]+$/).min(10),
  
  // Date validation
  date: Joi.date().iso(),
  
  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sortBy: Joi.string().default('created_at'),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc')
  }),
  
  // Common ID parameter
  idParam: Joi.object({
    id: Joi.alternatives().try(
      Joi.string().uuid({ version: 'uuidv4' }),
      Joi.number().integer().positive()
    )
  })
};

// Route-specific validation schemas
const validationSchemas = {
  // Auth schemas
  signup: Joi.object({
    email: schemas.email.required(),
    password: schemas.password.required(),
    name: Joi.string().min(2).max(100).required(),
    phone: schemas.phone.optional(),
    roles: Joi.array().items(
      Joi.string().valid('client', 'specialist', 'admin', 'owner', 'engineer')
    ).optional()
  }),
  
  login: Joi.object({
    email: schemas.email.required(),
    password: Joi.string().required()
  }),
  
  verifyTwoFactor: Joi.object({
    tempToken: Joi.string().required(),
    code: Joi.string().length(6).pattern(/^\d+$/).required()
  }),
  
  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),
  
  resetPasswordRequest: Joi.object({
    email: schemas.email.required()
  }),
  
  resetPassword: Joi.object({
    token: Joi.string().required(),
    newPassword: schemas.password.required()
  }),
  
  enableTwoFactor: Joi.object({
    code: Joi.string().length(6).pattern(/^\d+$/).required()
  }),
  
  // User schemas
  updateUser: Joi.object({
    name: Joi.string().min(2).max(100).optional(),
    phone: schemas.phone.optional(),
    address: Joi.string().max(500).optional(),
    specialization: Joi.object().optional(),
    subscriptionPlan: Joi.string().valid('basic', 'professional', 'premium').optional(),
    billingEnabled: Joi.boolean().optional(),
    canTrainClients: Joi.boolean().optional()
  }),
  
  // Measurement schemas
  createMeasurement: Joi.object({
    clientId: schemas.uuid.when('$userRole', {
      is: 'client',
      then: Joi.optional(),
      otherwise: Joi.required()
    }),
    date: schemas.date.required(),
    weight: Joi.number().positive().precision(2).optional(),
    bodyFat: Joi.number().min(0).max(100).precision(2).optional(),
    bmr: Joi.number().positive().integer().optional(),
    bloodPressure: Joi.string().pattern(/^\d{2,3}\/\d{2,3}$/).optional(),
    height: Joi.number().positive().precision(2).optional(),
    age: Joi.number().integer().min(0).max(150).optional(),
    gender: Joi.string().valid('male', 'female', 'other').optional(),
    activityLevel: Joi.string().valid('sedentary', 'light', 'moderate', 'active', 'veryActive').optional(),
    circumference: Joi.object({
      neck: Joi.number().positive().optional(),
      shoulders: Joi.number().positive().optional(),
      chest: Joi.number().positive().optional(),
      upperArm: Joi.number().positive().optional(),
      lowerArm: Joi.number().positive().optional(),
      waist: Joi.number().positive().optional(),
      hips: Joi.number().positive().optional(),
      upperThigh: Joi.number().positive().optional(),
      calf: Joi.number().positive().optional()
    }).optional(),
    caliper: Joi.object({
      chest: Joi.number().positive().optional(),
      abdominal: Joi.number().positive().optional(),
      thigh: Joi.number().positive().optional(),
      bicep: Joi.number().positive().optional(),
      tricep: Joi.number().positive().optional(),
      subscapular: Joi.number().positive().optional(),
      suprailiac: Joi.number().positive().optional(),
      lowerBack: Joi.number().positive().optional(),
      calf: Joi.number().positive().optional()
    }).optional()
  }),
  
  // Workout schemas
  createWorkout: Joi.object({
    clientId: schemas.uuid.when('$userRole', {
      is: 'client',
      then: Joi.optional(),
      otherwise: Joi.required()
    }),
    name: Joi.string().min(2).max(200).required(),
    exercises: Joi.array().items(
      Joi.object({
        name: Joi.string().required(),
        sets: Joi.number().integer().positive().required(),
        reps: Joi.number().integer().positive().required(),
        weight: Joi.number().min(0).optional(),
        restTime: Joi.number().integer().positive().optional(),
        specialistNote: Joi.string().max(500).optional()
      })
    ).min(1).required(),
    scheduledDate: schemas.date.optional(),
    youtubeLink: Joi.string().uri().optional(),
    notes: Joi.string().max(1000).optional()
  }),
  
  completeWorkout: Joi.object({
    exercises: Joi.array().items(
      Joi.object({
        id: Joi.number().required(),
        actualSets: Joi.number().integer().positive().required(),
        actualReps: Joi.number().integer().positive().required(),
        actualWeight: Joi.number().min(0).optional(),
        painLevel: Joi.number().integer().min(0).max(5).optional()
      })
    ).required(),
    moodFeedback: Joi.number().integer().min(1).max(5).optional(),
    duration: Joi.number().integer().positive().optional(),
    caloriesBurned: Joi.number().integer().positive().optional(),
    notes: Joi.string().max(1000).optional()
  }),
  
  // Nutrition schemas
  updateNutrition: Joi.object({
    clientId: schemas.uuid.when('$userRole', {
      is: 'client',
      then: Joi.optional(),
      otherwise: Joi.required()
    }),
    protein: Joi.object({
      target: Joi.number().min(0).required(),
      current: Joi.number().min(0).required()
    }).optional(),
    carbs: Joi.object({
      target: Joi.number().min(0).required(),
      current: Joi.number().min(0).required()
    }).optional(),
    fat: Joi.object({
      target: Joi.number().min(0).required(),
      current: Joi.number().min(0).required()
    }).optional(),
    calories: Joi.object({
      target: Joi.number().min(0).required(),
      current: Joi.number().min(0).required()
    }).optional(),
    fiber: Joi.object({
      target: Joi.number().min(0).required(),
      current: Joi.number().min(0).required()
    }).optional(),
    water: Joi.object({
      target: Joi.number().min(0).required(),
      current: Joi.number().min(0).required()
    }).optional(),
    mealPlan: Joi.object({
      breakfast: Joi.string().allow('').optional(),
      lunch: Joi.string().allow('').optional(),
      dinner: Joi.string().allow('').optional(),
      snacks: Joi.string().allow('').optional()
    }).optional(),
    restrictions: Joi.array().items(Joi.string()).optional(),
    supplements: Joi.array().items(Joi.string()).optional()
  }),
  
  // Goal schemas
  createGoal: Joi.object({
    clientId: schemas.uuid.when('$userRole', {
      is: 'client',
      then: Joi.optional(),
      otherwise: Joi.required()
    }),
    name: Joi.string().min(2).max(200).required(),
    target: Joi.number().required(),
    current: Joi.number().required(),
    deadline: schemas.date.required(),
    category: Joi.string().valid('weight', 'body-composition', 'performance', 'health', 'other').optional(),
    priority: Joi.string().valid('low', 'medium', 'high').optional(),
    milestones: Joi.array().items(
      Joi.object({
        date: schemas.date.required(),
        target: Joi.number().required(),
        achieved: Joi.boolean().optional()
      })
    ).optional()
  }),
  
  // Billing schemas
  createCheckout: Joi.object({
    priceId: Joi.string().required(),
    successUrl: Joi.string().uri().required(),
    cancelUrl: Joi.string().uri().required()
  }),
  
  // Message schemas
  sendMessage: Joi.object({
    recipientId: schemas.uuid.required(),
    text: Joi.string().min(1).max(5000).required(),
    attachmentUrl: Joi.string().uri().optional()
  }),
  
  markMessagesRead: Joi.object({
    messageIds: Joi.array().items(Joi.number().integer().positive()).min(1).required()
  }),
  
  // Training session schemas
  createTrainingSession: Joi.object({
    clientId: schemas.uuid.required(),
    date: schemas.date.required(),
    time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).required(),
    duration: Joi.number().integer().positive().default(60),
    type: Joi.string().max(100).required(),
    location: Joi.string().max(200).optional(),
    notes: Joi.string().max(1000).optional(),
    zoomLink: Joi.string().uri().optional()
  }),
  
  // Report schemas
  generateReport: Joi.object({
    type: Joi.string().valid('progress', 'measurements', 'workouts', 'nutrition', 'comprehensive').required(),
    clientId: schemas.uuid.when('$userRole', {
      is: 'client',
      then: Joi.optional(),
      otherwise: Joi.required()
    }),
    startDate: schemas.date.required(),
    endDate: schemas.date.required(),
    format: Joi.string().valid('pdf', 'excel', 'json').default('pdf')
  })
};

// Helper to validate query parameters
const validateQuery = (schema) => validateRequest(schema, 'query');

// Helper to validate route parameters
const validateParams = (schema) => validateRequest(schema, 'params');

// Helper to validate with context (e.g., user role)
const validateWithContext = (schema, property = 'body') => {
  return (req, res, next) => {
    const context = {
      userRole: req.user?.roles ? JSON.parse(req.user.roles)[0] : null,
      userId: req.user?.id
    };
    
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      stripUnknown: true,
      context
    });

    if (error) {
      const errors = error.details.reduce((acc, detail) => {
        const key = detail.path.join('.');
        acc[key] = detail.message;
        return acc;
      }, {});

      return res.status(400).json({
        error: 'Validation failed',
        details: errors
      });
    }

    req[property] = value;
    next();
  };
};

// Export middleware and schemas
module.exports = {
  validateRequest,
  validateQuery,
  validateParams,
  validateWithContext,
  schemas,
  validationSchemas
};