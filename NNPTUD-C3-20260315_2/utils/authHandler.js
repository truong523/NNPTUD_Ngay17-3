const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const userController = require('../controllers/users');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith("Bearer ")) {
                return res.status(401).send({ message: "Chưa đăng nhập" });
            }
            
            token = token.split(' ')[1];
            const publicKey = fs.readFileSync(path.resolve(__dirname, '../public.pem'), 'utf8');

            // Xác thực thuật toán RS256
            let decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            let user = await userController.GetUserById(decoded.id);

            if (!user) return res.status(401).send({ message: "User không tồn tại" });

            req.user = user;
            next();
        } catch (error) {
            return res.status(401).send({ message: "Xác thực thất bại" });
        }
    }
};