const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const { sequelize } = require("./models");
const authRoutes = require("./routes/authRoutes");
const errorHandler = require("./middlewares/errorHandler");

const app = express();
const PORT = process.env.PORT || 5000;

// Core Middlewares
app.use(
  cors({
    origin: process.env.CLIENT_URL || true,
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Root Healthcheck Endpoint
app.get("/", (req, res) => {
  res.json({
    status: "online",
    system: "Custom OAuth 2.0 / JWT Authentication Server",
    version: "1.0.0",
    endpoints: {
      register: "POST /auth/register",
      login: "POST /auth/login",
      profile: "GET /auth/profile (Protected)",
      refresh: "POST /auth/refresh",
      logout: "POST /auth/logout",
    },
  });
});

// Route Mounting
app.use("/auth", authRoutes);
app.use("/api/auth", authRoutes); // Alias for compatibility

// Centralized Error Handler Middleware
app.use(errorHandler);

// Database Sync and Server Startup
const startServer = async () => {
  try {
    await sequelize.authenticate();
    console.log("Database connection established successfully.");

    // Sync models with database
    await sequelize.sync({ force: false });
    console.log("Database models synchronized.");

    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Unable to connect to the database:", error);
    process.exit(1);
  }
};

startServer();

module.exports = app;
