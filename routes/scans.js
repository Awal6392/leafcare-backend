const express = require('express');
const {
  upload,
  saveScanResult,
  getUserScans,
  getScanResult,
  updateScanResult,
  deleteScanResult,
  getScanStats
} = require('../controllers/scanController');
const { protect } = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(protect);

// Routes
router.route('/')
  .get(getUserScans)
  .post(upload, saveScanResult);

router.get('/stats', getScanStats);

router.route('/:id')
  .get(getScanResult)
  .put(updateScanResult)
  .delete(deleteScanResult);

module.exports = router;