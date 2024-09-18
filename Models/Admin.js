const mongoose = require("mongoose");

const adminSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobileNumber: { type: String, required: true },
    otp: { type: String },
    otpExpiry: { type: Date },
    sessions: [
      {
        sessionId: { type: String },
        createdAt: { type: Date, default: Date.now },
        expiresAt: { type: Date }, // Expiry time for the session
      },
    ],
    resetPasswordToken: { type: String }, // Field for storing the hashed reset token
    resetPasswordExpiry: { type: Date }, // Field for storing the token expiry time
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Admin", adminSchema);
