const Admin = require("../Models/Admin");

const removeExpiredSessions = async () => {
  try {
    const admins = await Admin.find({
      "sessions.expiresAt": { $lt: new Date() },
    });

    for (const admin of admins) {
      admin.sessions = admin.sessions.filter(
        (session) => new Date(session.expiresAt) > new Date()
      );
      await admin.save();
    }
  } catch (error) {
    console.error("Error while removing expired sessions:", error);
  }
};

module.exports = { removeExpiredSessions };
