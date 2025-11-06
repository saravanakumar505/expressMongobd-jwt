import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import profileRouter from "./routes/profileRoutes.js";

dotenv.config();

const app = express();
app.set("trust proxy", 1)

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, //15mins
    max: 100,
    message: "Too many requests, try again later",
  })
);

app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use("/", profileRouter);

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log(`MongoDB connected`))
  .catch((err) => console.log(err));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`server running on http://localhost:${PORT}`)
);
