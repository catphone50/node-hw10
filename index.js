import express from "express";
import cors from "cors";
import sequelize from "./config/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";
import logRequest from "./middleware/logRequest.js";
import authorizeRole from "./middleware/authRole.js";
import authenticateJWT from "./middleware/authenticateJWT.js";

const app = express();
const PORT = process.env.PORT || "3000";
const jwtSecret = process.env.JWT_SECRET_KEY || "secret_key";
const jwtTime = process.env.JWT_TIME || "1h";

let users = [
  {
    id: "1",
    email: "user@example.com",
    username: "Jane",
    role: "user",
    password: bcrypt.hashSync("user123", 5),
  },
  {
    id: "2",
    email: "user2@example.com",
    username: "John",
    role: "admin",
    password: bcrypt.hashSync("123", 5),
  },
];

app.use(cors());
app.use(express.json());
app.use(logRequest);

app.get("/", (req, res) => {
  res.send("My Server");
});

app.get("/admin", authenticateJWT, authorizeRole("admin"), (req, res) => {
  res.json({
    message: "Welcome, Admin! You have access to this protected route.",
  });
});

app.get("/profile", authenticateJWT, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
    message: "Here is your personal information.",
  });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return res.status(404).json({ message: "Invalid credentials" });
    }
    const passwordsMatch = await bcrypt.compare(password, user.password);
    if (!passwordsMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      jwtSecret,
      {
        expiresIn: jwtTime,
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Something went wrong." });
  }
});

app.put("/update-email", authenticateJWT, (req, res) => {
  const { email } = req.body;
  const userId = req.user.id;

  const user = users.find((u) => u.id === userId);

  if (user) {
    user.email = email;
    return res.status(200).json({ message: "Email update", email: user.email });
  } else {
    return res.status(404).json({ message: "No user data" });
  }
});

app.delete("/delete-account", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  const initialLength = users.length;
  users = users.filter((u) => u.id !== userId);

  if (users.length < initialLength) {
    return res.status(200).json({ message: "User was deleted " });
  } else {
    return res.status(404).json({ message: "No user data" });
  }
});

app.put("/update-role", authenticateJWT, authorizeRole("admin"), (req, res) => {
  const { role, userId } = req.body;

  const user = users.find((u) => u.id === userId);

  if (user) {
    user.role = role;
    return res
      .status(200)
      .json({ message: "Role update", role: user.role, name: user.username });
  } else {
    return res.status(404).json({ message: "No user data" });
  }
});

app.post("/refresh-token", authenticateJWT, (req, res) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(403)
      .json({ message: "Authorization header is missing or malformed" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token was is not valid" });
    }

    const newToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      jwtSecret,
      {
        expiresIn: jwtTime,
      }
    );

    return res.status(200).json({ token: newToken });
  });
});

app.listen(PORT, async () => {
  try {
    await sequelize.authenticate();
    console.log(`server connect to port http://localhost:${PORT}`);
  } catch (error) {
    console.error("Error to connect", error);
  }
});

// fetch("http://localhost:3333/login", { method: "POST", body: JSON.stringify({email: "user@example.com", password: "user123"}), headers: { "Content-Type": "application/json"} })
