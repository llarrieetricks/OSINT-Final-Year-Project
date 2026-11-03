const express = require("express");
const router = express.Router();
const {
  createAssessment,
  getAssessmentByUrl,
} = require("../controllers/assessmentController");

router.post("/", createAssessment);
router.get("/lookup", getAssessmentByUrl);

module.exports = router;
