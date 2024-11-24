import jwt from "jsonwebtoken";

export default function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, data) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "Forbidden: invalid or expired token" });
      }

      req.user = data;
      next();
    });
  } else {
    return res
      .status(401)
      .json({ message: "Unauthorized: No token provided." });
  }
}
