const mongoose = require('mongoose');

const scanResultSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  imagePath: {
    type: String,
    required: true
  },
  imageUrl: String,
  
  // AI Prediction Results
  prediction: {
    disease: {
      type: String,
      required: true
    },
    confidence: {
      type: Number,
      required: true,
      min: 0,
      max: 100
    },
    isHealthy: {
      type: Boolean,
      required: true
    }
  },
  
  // Location data (if available)
  location: {
    latitude: Number,
    longitude: Number,
    address: String
  },
  
  // Additional metadata
  metadata: {
    deviceInfo: {
      platform: String,
      version: String,
      model: String
    },
    imageInfo: {
      width: Number,
      height: Number,
      size: Number,
      format: String
    },
    weather: {
      temperature: Number,
      humidity: Number,
      condition: String
    }
  },
  
  // User notes and feedback
  userNotes: {
    type: String,
    maxlength: [500, 'Notes cannot exceed 500 characters']
  },
  
  // Treatment tracking
  treatment: {
    applied: {
      type: Boolean,
      default: false
    },
    treatmentType: String,
    treatmentDate: Date,
    followUpRequired: {
      type: Boolean,
      default: false
    },
    followUpDate: Date
  },
  
  // Feedback on prediction accuracy
  feedback: {
    isAccurate: Boolean,
    actualDisease: String,
    comments: String,
    submittedAt: Date
  },
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update timestamp before saving
scanResultSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Create indexes for better query performance
scanResultSchema.index({ user: 1, createdAt: -1 });
scanResultSchema.index({ 'prediction.disease': 1 });
scanResultSchema.index({ 'prediction.isHealthy': 1 });
scanResultSchema.index({ createdAt: -1 });

// Virtual for formatted date
scanResultSchema.virtual('formattedDate').get(function() {
  return this.createdAt.toLocaleDateString();
});

// Instance method to update user statistics
scanResultSchema.methods.updateUserStats = async function() {
  const User = mongoose.model('User');
  const user = await User.findById(this.user);
  
  if (user) {
    const scanType = this.prediction.isHealthy ? 'healthy' : 'disease';
    await user.updateStats(scanType);
  }
};

module.exports = mongoose.model('ScanResult', scanResultSchema);