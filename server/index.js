require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");
const assessmentRoutes = require("./routes/assessmentRoutes");

const app = express();
app.use(cors());
app.use(express.json());
app.use("/api/assess", assessmentRoutes);

app.get("/", (req, res) => {
  res.json({ status: "OSINT Phishing Risk Assessment API running" });
});

const PORT = process.env.PORT || 5000;
connectDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
