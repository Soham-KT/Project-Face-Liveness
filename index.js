const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const AdminRoutes = require("./Routes/Adminroute");
const cors = require("cors");
require("dotenv").config();
const { removeExpiredSessions } = require("./utils/sessionCleanup");

const app = express();

// Add CORS middleware
app.use(
  cors({
    origin: function (origin, callback) {
      callback(null, true);
    },
    credentials: true, // Allow cookies to be sent
  })
);

app.use(express.json());

mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => {
    console.log("Connected to Database");
  })
  .catch((error) => {
    console.error("Database connection failed:", error);
  });

app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, 
  })
);

app.use("/admin", AdminRoutes);

// Cleaning sessions
setInterval(removeExpiredSessions, 30 * 60 * 1000); // every 30 minutes

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
