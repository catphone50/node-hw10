export default function authorizeRole(role) {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res
          .status(401)
          .json({ message: "Unauthorized: No user data available." });
      }

      if (req.user.role !== role) {
        return res.status(403).json({
          message: "Forbidden: You don't have access to this resource.",
        });
      }

      next();
    } catch (error) {
      console.error("Authorization error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  };
}
