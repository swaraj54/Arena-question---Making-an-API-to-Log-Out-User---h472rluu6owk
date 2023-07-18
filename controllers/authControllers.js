const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const JWT_SECRET = 'newtonSchool';

/*
You need to implement a logout controller which takes an authorization token as input, verifies the token, clears the cookie and logs out the user.

Instructions:
The controller expects an HTTP POST request with an authorization token in the request header.

If the authorization token is missing, the controller should respond with a 401 Unauthorized status and a JSON object containing a 'message' field with value 'Authentication failed: Missing token.', and a 'status' field with value 'Error'.

If the authorization token is invalid, the controller should respond with a 401 Unauthorized status and a JSON object containing a 'message' field with value 'Authentication failed: Invalid token.', and a 'status' field with value 'Error'.

If the authorization token is valid, the controller should clear the cookie and respond with a 200 OK status and a JSON object containing a 'message' field with value 'Logged out successfully.', and a 'status' field with value 'Success'.

If there is an error during the JWT verification process or clearing the cookie, the controller should respond with a 500 Internal Server Error status and a JSON object containing a 'message' field with value 'Something went wrong', a 'status' field with value 'Error', and an 'error' field with the error object.

Input:
Authorization Token

Output:
{
"message": "Logged out successfully.",
"status": "Success"
}
*/

const logout = (req, res) => {
    const token = req.headers.authorization;
    // Write your code here :)
};

const signup = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const user = await User.create({
            username,
            email,
            password,
        });
        res.status(201).json({
            status: 'success',
            data: {
                user,
            },
        });
    } catch (err) {
        res.status(400).json({
            status: 'error',
            message: err.message,
        });
    }
}

const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: 'Please provide email and password',
            status: 'Error',
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                message: 'Invalid email or password',
                status: 'Error',
                error: 'Invalid Credentials',
            });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);
        if (!passwordMatches) {
            return res.status(401).json({
                message: 'Invalid email or password',
                status: 'Error',
                error: 'Invalid Credentials',
            });
        }

        const token = jwt.sign({ userId: user._id, username: user.username, email: user.email, role: user.role }, JWT_SECRET, {
            expiresIn: '1h',
        });

        res.status(200).json({ token, status: 'Success' });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            message: 'Something went wrong',
            status: 'Error',
            error: err,
        });
    }
};

const decodeToken = (req, res) => {
    try {
        let { token } = req.body;
        console.log(token);
        const decodedToken = jwt.verify(token, JWT_SECRET);
        res.status(200).json({ payload: decodedToken, status: 'Success' });
    } catch (err) {
        console.error(err);
        res.status(401).json({ message: 'Invalid token' });
    }
};

module.exports = { login, logout, signup, decodeToken };