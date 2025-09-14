const ScanResult = require('../models/ScanResult');
const User = require('../models/User');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = 'uploads/scans/';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    cb(null, `${req.user.id}_${Date.now()}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10485760 // 10MB
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = /jpeg|jpg|png/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only JPEG, JPG and PNG images are allowed'));
    }
  }
});

// @desc    Save scan result
// @route   POST /api/scans
// @access  Private
const saveScanResult = async (req, res) => {
  try {
    const {
      disease,
      confidence,
      isHealthy,
      location,
      metadata,
      userNotes
    } = req.body;

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'Image file is required'
      });
    }

    // Create image URL
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/scans/${req.file.filename}`;

    const scanResult = await ScanResult.create({
      user: req.user.id,
      imagePath: req.file.path,
      imageUrl: imageUrl,
      prediction: {
        disease,
        confidence: parseFloat(confidence),
        isHealthy: isHealthy === 'true' || isHealthy === true
      },
      location: location ? JSON.parse(location) : undefined,
      metadata: metadata ? JSON.parse(metadata) : undefined,
      userNotes
    });

    // Update user statistics
    await scanResult.updateUserStats();

    // Populate user data
    await scanResult.populate('user', 'name email');

    res.status(201).json({
      success: true,
      data: scanResult
    });
  } catch (error) {
    console.error('Save scan result error:', error);
    res.status(500).json({
      success: false,
      message: 'Error saving scan result'
    });
  }
};

// @desc    Get user's scan results
// @route   GET /api/scans
// @access  Private
const getUserScans = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const startIndex = (page - 1) * limit;

    const total = await ScanResult.countDocuments({ user: req.user.id });
    
    const scans = await ScanResult.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(startIndex)
      .select('-__v');

    // Calculate pagination info
    const pagination = {};
    if (startIndex + limit < total) {
      pagination.next = {
        page: page + 1,
        limit
      };
    }

    if (startIndex > 0) {
      pagination.prev = {
        page: page - 1,
        limit
      };
    }

    res.status(200).json({
      success: true,
      count: scans.length,
      total,
      pagination,
      data: scans
    });
  } catch (error) {
    console.error('Get user scans error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving scan results'
    });
  }
};

// @desc    Get specific scan result
// @route   GET /api/scans/:id
// @access  Private
const getScanResult = async (req, res) => {
  try {
    const scan = await ScanResult.findOne({
      _id: req.params.id,
      user: req.user.id
    }).populate('user', 'name email');

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan result not found'
      });
    }

    res.status(200).json({
      success: true,
      data: scan
    });
  } catch (error) {
    console.error('Get scan result error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving scan result'
    });
  }
};

// @desc    Update scan result
// @route   PUT /api/scans/:id
// @access  Private
const updateScanResult = async (req, res) => {
  try {
    const { userNotes, treatment, feedback } = req.body;

    const scan = await ScanResult.findOne({
      _id: req.params.id,
      user: req.user.id
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan result not found'
      });
    }

    // Update allowed fields
    if (userNotes !== undefined) scan.userNotes = userNotes;
    if (treatment) scan.treatment = { ...scan.treatment, ...treatment };
    if (feedback) scan.feedback = { ...feedback, submittedAt: new Date() };

    await scan.save();

    res.status(200).json({
      success: true,
      data: scan
    });
  } catch (error) {
    console.error('Update scan result error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating scan result'
    });
  }
};

// @desc    Delete scan result
// @route   DELETE /api/scans/:id
// @access  Private
const deleteScanResult = async (req, res) => {
  try {
    const scan = await ScanResult.findOne({
      _id: req.params.id,
      user: req.user.id
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan result not found'
      });
    }

    // Delete image file
    if (fs.existsSync(scan.imagePath)) {
      fs.unlinkSync(scan.imagePath);
    }

    await scan.deleteOne();

    res.status(200).json({
      success: true,
      message: 'Scan result deleted successfully'
    });
  } catch (error) {
    console.error('Delete scan result error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting scan result'
    });
  }
};
 
// @desc    Get scan statistics
// @route   GET /api/scans/stats
// @access  Private
const getScanStats = async (req, res) => {
  try {
    const userId = req.user.id;
    const { period = '30d' } = req.query;

    // Calculate date range
    let startDate = new Date();
    switch (period) {
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      case '1y':
        startDate.setFullYear(startDate.getFullYear() - 1);
        break;
      default:
        startDate.setDate(startDate.getDate() - 30);
    }

    // Aggregate statistics
    const stats = await ScanResult.aggregate([
      {
        $match: {
          user: req.user._id,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: null,
          totalScans: { $sum: 1 },
          healthyScans: {
            $sum: { $cond: [{ $eq: ['$prediction.isHealthy', true] }, 1, 0] }
          },
          diseaseScans: {
            $sum: { $cond: [{ $eq: ['$prediction.isHealthy', false] }, 1, 0] }
          },
          avgConfidence: { $avg: '$prediction.confidence' },
          diseases: { $push: { $cond: [{ $eq: ['$prediction.isHealthy', false] }, '$prediction.disease', null] } }
        }
      }
    ]);

    // Get disease breakdown
    const diseaseBreakdown = await ScanResult.aggregate([
      {
        $match: {
          user: req.user._id,
          createdAt: { $gte: startDate },
          'prediction.isHealthy': false
        }
      },
      {
        $group: {
          _id: '$prediction.disease',
          count: { $sum: 1 },
          avgConfidence: { $avg: '$prediction.confidence' }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    const result = {
      period,
      stats: stats[0] || {
        totalScans: 0,
        healthyScans: 0,
        diseaseScans: 0,
        avgConfidence: 0
      },
      diseaseBreakdown
    };

    res.status(200).json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('Get scan stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving scan statistics'
    });
  }
};

module.exports = {
  upload: upload.single('image'),
  saveScanResult,
  getUserScans,
  getScanResult,
  updateScanResult,
  deleteScanResult,
  getScanStats
};