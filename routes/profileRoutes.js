import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import profiles from "../models/profiles.js";

const router = express.Router();

// ✅ Rate limiter for login
const loginLimiter = rateLimit({
  windowMs: 20 * 60 * 1000, // 20 minutes
  max: 50,
  message: "Too many requests, try again later",
});

// ✅ Token verification middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "no token provided" });
  }

  const tokenSignature = authHeader.split(" ")[1];

  jwt.verify(tokenSignature, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "access token expired" });
      } else {
        return res.status(403).json({ message: "invalid token" });
      }
    }

    req.profile = decoded;
    next(); // ✅ move here
  });
}

// ✅ Register route
router.post("/register", async (req, res) => {
  try {
    const { name, email, role, adminCode, imageUrl, password } = req.body;
    if (!name || !email || !role || !imageUrl || !password) {
      return res.status(400).json({ message: "all fields are required" });
    }

    const existingUser = await profiles.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "email already registered" });
    }

    let userRole = role;
    if (role === "admin" && adminCode !== process.env.ADMIN_CODE) {
      return res.status(403).json({ message: "invalid admin code" });
    } else if (role !== "admin") {
      userRole = "user";
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await profiles.create({
      name,
      email,
      password: hashedPassword,
      role: userRole,
      imageUrl,
    });

    res.status(200).json({ message: `object created with role - ${userRole}` });
  } catch (error) {
    res.status(500).json({ message: `something went wrong ${error}` });
  }
});

// ✅ Login route
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const profile = await profiles.findOne({ email });
    if (!profile) {
      return res.status(404).json({ message: `object with ${email} not found` });
    }

    const isMatch = await bcrypt.compare(password, profile.password);
    if (!isMatch) {
      return res.status(401).json({ message: "invalid password" });
    }

    const accessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { id: profile._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "2d" }
    );

    profile.refreshToken = refreshToken;
    await profile.save();

    res.status(200).json({ id: profile._id, accessToken, refreshToken, role: profile.role });
  } catch (error) {
    res.status(500).json({ message: `something went wrong ${error}` });
  }
});

// ✅ Get all or single profile
router.get("/", verifyToken, async (req, res) => {
  try {
    if (req.profile.role === "admin") {
      const profileData = await profiles.find({}, "-password -refreshToken");
      res.status(200).json(profileData);
    } else {
      const profile = await profiles.findById(req.profile.id);
      res.status(200).json(profile);
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ Update
router.put("/:id", verifyToken, async (req, res) => {
  if (req.profile.role !== "admin") {
    return res.status(403).json({
      message: `access denied because you are a ${req.profile.role}`,
    });
  }

  const { name, role, imageUrl } = req.body;
  const updatedRole = role === "admin" ? "admin" : "user";

  await profiles.findByIdAndUpdate(req.params.id, { name, role: updatedRole, imageUrl });
  res.status(200).json({ message: `object with id ${req.params.id} is edited` });
});

// ✅ Delete
router.delete("/:id", verifyToken, async (req, res) => {
  if (req.profile.role !== "admin") {
    return res.status(403).json({
      message: `access denied because you are a ${req.profile.role}`,
    });
  }

  await profiles.findByIdAndDelete(req.params.id);
  res.status(200).json({ message: `object with id ${req.params.id} has been deleted` });
});

// ✅ Refresh token
router.post("/refresh", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: "no refresh token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const profile = await profiles.findById(decoded.id);
    if (!profile) return res.status(403).json({ message: "invalid refresh token" });

    // ✅ Compare stored refresh token
    if (profile.refreshToken !== token) {
      return res.status(403).json({ message: "refresh token mismatch" });
    }

    const newAccessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(403).json({ message: "invalid or expired refresh token" });
  }
});

// ✅ Get single profile by ID (admin only)
router.get("/profile/:id", verifyToken, async (req, res) => {
  try {
    if (req.profile.role !== "admin") {
      return res.status(403).json({
        message: `access denied because you are a ${req.profile.role}`,
      });
    }

    const profile = await profiles.findById(req.params.id, "-password -refreshToken");
    if (!profile) return res.status(404).json({ message: "profile not found" });

    res.status(200).json(profile);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

export default router;
