const userModel = require("../schemas/users");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

module.exports = {
    // Login trả về Token RS256 (Dùng Private Key)
    QueryLogin: async function (username, password) {
        if (!username || !password) return false;

        let user = await userModel.findOne({ username, isDeleted: false });

        if (user && bcrypt.compareSync(password, user.password)) {
            // Đọc Private Key từ thư mục gốc
            const privateKey = fs.readFileSync(path.resolve(__dirname, '../private.pem'), 'utf8');

            return jwt.sign(
                { id: user._id, username: user.username }, 
                privateKey, 
                { algorithm: 'RS256', expiresIn: '1d' }
            );
        }
        return false;
    },

    // Đổi mật khẩu (Cập nhật trực tiếp vào MongoDB)
    ChangePassword: async function (userId, oldPassword, newPassword) {
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            throw new Error("Mật khẩu mới phải có ít nhất 8 ký tự, gồm cả chữ và số.");
        }

        let user = await userModel.findById(userId);
        if (!user) throw new Error("Người dùng không tồn tại.");

        if (!bcrypt.compareSync(oldPassword, user.password)) {
            throw new Error("Mật khẩu cũ không chính xác.");
        }

        user.password = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10));
        await user.save();
        return true;
    },

    GetUserById: async function (id) {
        try {
            return await userModel.findOne({ _id: id, isDeleted: false });
        } catch (error) {
            return null;
        }
    }
};