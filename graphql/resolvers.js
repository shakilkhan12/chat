const { User } = require("../models")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { UserInputError, AuthenticationError } = require("apollo-server")
const { JWT_SECRET } = require("../config/env.json")
const { Op } = require("sequelize")
module.exports = {
    Query: {
        getUsers: async (parent, args, context) => {

            try {
                let user;
                if (context.req && context.req.headers.authorization) {
                    const token = context.req.headers.authorization.split('Bearer ')[1]

                    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
                        if (err) {
                            throw new AuthenticationError('utherization error')
                        }
                        user = decodedToken;
                        console.log(user)
                    })
                }
                const users = await User.findAll({ where: { username: { [Op.ne]: user.username } } });
                return users;
            } catch (err) {
                console.log(err)
                throw err;
            }
        },
        login: async (_, args) => {
            const { username, password } = args
            let errors = {}
            try {
                if (username.trim() === '') errors.username = "username is reqired";
                if (password === '') errors.password = "password is reqired";
                if (Object.keys(errors).length > 0) {
                    throw new UserInputError('error: ', { errors })
                }
                const user = await User.findOne({ where: { username } });
                if (!user) {
                    errors.username = "username not found";
                    throw new UserInputError('error: ', { errors })
                }

                const correctPassword = await bcrypt.compare(password, user.password);
                if (!correctPassword) {
                    errors.password = "password is incorrect";
                    throw new AuthenticationError('password is incorrect', { errors })
                }
                console.log(user)
                const token = jwt.sign({
                    username
                }, JWT_SECRET, { expiresIn: 60 * 60 });
                return {
                    ...user.toJSON(),
                    createdAt: user.createdAt.toISOString(),
                    token
                }
            } catch (error) {
                console.log(error);
                throw error;
            }
        }
    },
    Mutation: {
        register: async (_, args) => {
            let { username, email, password, confirmPassword } = args
            let errors = {}
            try {

                // TODO: Validate input data
                if (email.trim() === '') errors.email = "Email is required"
                if (username.trim() === '') errors.username = "Username is required"
                if (password.trim() === '') errors.password = "Password is required"
                if (confirmPassword.trim() === '') errors.confirmPassword = "Confirm password is required"
                if (password !== confirmPassword) errors.confirmPassword = "Password does not matched"

                // TODO: Check if email/username is exists
                // const userByUsername = await User.findOne({ where: { username } });
                // const userByEmail = await User.findOne({ where: { email } });
                // if (userByUsername) errors.username = "username is taken";
                // if (userByEmail) errors.email = "email is taken";
                if (Object.keys(errors).length > 0) {
                    throw errors;
                }
                // TODO:  Hash password
                password = await bcrypt.hash(password, 6)

                // TODO: Create user
                const user = await User.create({
                    username, email, password
                })

                // TODO: Return user
                return user;
            } catch (error) {
                console.log(error)
                if (error.name === "SequelizeUniqueConstraintError") {
                    error.errors.forEach(e => (errors[e.path] = `${e.path} is already taken`))
                } else if (error.name === "SequelizeValidationError") {
                    error.errors.forEach(e => errors[e.path] = e.message)
                }
                throw new UserInputError('Bad Input ', { errors });
            }
        }
    }
};