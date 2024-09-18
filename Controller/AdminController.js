const Admin = require("../Models/Admin");
const UnverifiedAdmin = require("../Models/UnverifiedAdmin");
const {
  sendOtpToEmail,
  sendResetLinkToEmail,
} = require("../Config/nodemailer");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const signUp = async (req, res) => {
  const { name, email, mobileNumber, password } = req.body;

  try {
    const existingAdmin = await UnverifiedAdmin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ error: "Admin already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000);
    const otpExpiry = Date.now() + 2 * 24 * 60 * 60 * 1000; // 2 days

    const newAdmin = new UnverifiedAdmin({
      name,
      email,
      mobileNumber,
      password: hashedPassword,
      otp,
      otpExpiry,
    });

    await newAdmin.save();

    // Custom text for the email sent to the super admin
    const customText = `${name} is trying to sign up as an admin. His email is ${email} and the OTP is ${otp}.`;

    // Send OTP to the super admin
    await sendOtpToEmail(process.env.EMAIL_USER, otp, customText);

    res
      .status(200)
      .json({ message: "OTP sent to the super admin. Awaiting verification." });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

const verifyOtppasscode = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const unverifiedAdmin = await UnverifiedAdmin.findOne({ email });

    if (!unverifiedAdmin) {
      return res.status(404).json({ error: "Unverified admin not found." });
    }

    if (unverifiedAdmin.otp !== otp || unverifiedAdmin.otpExpiry < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired OTP." });
    }

    const { name, mobileNumber, password } = unverifiedAdmin;
    const admin = new Admin({
      name,
      email,
      mobileNumber,
      password,
    });

    await admin.save();
    await UnverifiedAdmin.deleteOne({ email });

    res.status(200).json({
      success: true,
      message: "Verification successful. You can now log in.",
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const isPasswordMatch = await bcrypt.compare(password, admin.password);

    if (!isPasswordMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000); // Generate OTP
    const otpExpiry = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes

    // Store the OTP and expiry in the database
    admin.otp = otp;
    admin.otpExpiry = otpExpiry;
    await admin.save();

    await sendOtpToEmail(email, otp);

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Check if OTP matches and is not expired
    if (admin.otp !== otp || Date.now() > admin.otpExpiry) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // Clear OTP and OTP expiry after successful verification
    admin.otp = null;
    admin.otpExpiry = null;

    // Generate session ID and set expiry to 6 hours from now
    const sessionId = crypto.randomBytes(16).toString("hex");
    const expiresAt = new Date(Date.now() + 6 * 60 * 60 * 1000); // 6 hours from now

    admin.sessions.push({ sessionId, expiresAt });
    await admin.save();

    res.status(200).json({
      message: "Login successful",
      sessionId,
      adminId: admin._id,
      name: admin.name,
      email: admin.email,
      mobileNumber: admin.mobileNumber,
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

const verifySession = async (req, res) => {
  const { sessionId } = req.body;

  try {
    const admin = await Admin.findOne({ "sessions.sessionId": sessionId });

    if (!admin) {
      return res.status(401).json({ valid: false, error: "Session not found" });
    }

    const session = admin.sessions.find((s) => s.sessionId === sessionId);

    // Check if session has expired
    if (new Date() > session.expiresAt) {
      return res.status(401).json({ valid: false, error: "Session expired" });
    }

    res.status(200).json({ valid: true });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Generate a reset token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Hash the reset token before saving to the database
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Set token expiry time (10 minutes from now)
    const tokenExpiry = Date.now() + 10 * 60 * 1000;

    // Save the hashed token and expiry in the database
    admin.resetPasswordToken = hashedToken;
    admin.resetPasswordExpiry = tokenExpiry;
    await admin.save();

    // Construct the reset link
    const resetLink = `${process.env.FRONTEND_URL}/reset_password?token=${resetToken}&email=${email}`;

    // Send the reset link to the admin's email
    await sendResetLinkToEmail(email, resetLink);

    res.status(200).json({ message: "Password reset link sent successfully" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

const resetPassword = async (req, res) => {
  const { token, email, newPassword } = req.body;

  try {
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Verify the reset token
    const isTokenValid = await bcrypt.compare(
      token,
      admin.resetPasswordToken
    );

    if (!isTokenValid || Date.now() > admin.resetPasswordExpiry) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    // Hash the new password and update it
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;

    // Clear the reset token and expiry
    admin.resetPasswordToken = null;
    admin.resetPasswordExpiry = null;

    await admin.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

module.exports = {
  login,
  verifyOtp,
  verifySession,
  signUp,
  verifyOtppasscode,
  forgotPassword,
  resetPassword,
};
