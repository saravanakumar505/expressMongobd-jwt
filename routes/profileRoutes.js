import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import profiles from "../models/profiles.js";

const router = express.Router();

const app = express();

const loginLimiter = app.use(
  rateLimit({
    windowMs: 20 * 60 * 1000, //15mins
    max: 5,
    message: "Too many requests, try again later",
  })
);

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

    //     {
    //   id: "6740e7e2b8f7c5b9c3a9e412",   // the user's MongoDB _id
    //   role: "admin",                   // or "user"
    //   iat: 1730430245,                 // "issued at" timestamp (auto added by JWT)
    //   exp: 1730430845                  // "expires at" timestamp (auto added by JWT)
    // }
  });

  next();
}

router.post("/api/register", async (req, res) => {
  try {
    const { name, email, role, adminCode, imageUrl, password } = req.body;
    console.log(adminCode);
    
    if (!name || !email || !role || !imageUrl || !password) {
      return res.status(400).json({ message: "all fields are required" });
    }

    let userRole = role;
    if (role === "admin" && adminCode === process.env.ADMIN_CODE) {
      return res
        .status(403)
        .json({ message: `invalid admin code -${adminCode}` });
    } else if (role !== "admin") {userRole = "user"};

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

router.post("/api/login", loginLimiter, async (req, res) => {
  console.log("trigg");
  try {
    const { email, password } = req.body;

    const profile = await profiles.findOne({ email });
    if (!profile) {
      return res
        .status(404)
        .json({ message: `object with ${email} not found` });
    }

    const isMatch = await bcrypt.compare(password, profile.password);
    if (!isMatch) {
      return res.status(401).json({ message: "invalid password" });
    }

    const accessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_SECRET,
      { expiresIn: "15min" }
    );

    const refreshToken = jwt.sign(
      { id: profile._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "2d" }
    );

    profile.refreshToken = refreshToken;
    await profile.save();
    res.status(200).json({ accessToken, refreshToken, role: profile.role });
  } catch (error) {
    res.status(500).json({ message: `something went wrong ${error}` });
  }
});

router.get("/", verifyToken, async (req, res) => {
  console.log("get");
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

router.put("/:id", verifyToken, async (req, res) => {
  if (req.profile.role !== "admin") {
    return res.status(403).json({
      message: `access denied because your are a ${req.profile.role}`,
    });
  }
  let { name, role, imageUrl } = req.body;

  let userRole = "user";
  if (role !== "admin") {
    role = userRole;
  }
  await profiles.findByIdAndUpdate(
    req.params.id,
    { name, role, imageUrl },
    { new: true }
  );
  res
    .status(200)
    .json({ message: `object with id: ${req.params.id} is edited` });
});

router.delete("/:id", verifyToken, async (req, res) => {
  console.log(req.params.id);
  if (req.profile.role !== "admin") {
    return res.status(403).json({
      message: `access denied because your are a ${req.profile.role}`,
    });
  }

  await profiles.findByIdAndDelete(req.params.id);
  res
    .status(200)
    .json({ message: `object with id ${req.params.id} has been deleted` });
});

router.post("/refresh", async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).json({ message: "no refresh token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

    console.log(decoded);

    const profile = await profiles.findById(decoded.id);
    if (!profile) {
      return res.status(403).json({ message: "invalid refresh token" });
    }
    const newAccesToken = jwt.sign(
      {
        id: profile._id,
        role: profile.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "15min" }
    );
    res.status(200).json({ accessToken: newAccesToken });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

export default router;

// npm install jsonwebtoken bcryptjs
