import mongoose from "mongoose";

const profileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  imageUrl: { type: String, default: "" },
  refreshToken: { type: String, default: "" },
});

const profiles = mongoose.model("profiles", profileSchema);
export default profiles;


// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5MDk5Y2ZjZWRlMzU4ZTgyMzlhNGFhNyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc2MjMzNDI0MCwiZXhwIjoxNzYyMzM1MTQwfQ.Kg_7OGqFuZJB0LEDygbXwSBCSxyF8WSvlZNEDHIMqDQ