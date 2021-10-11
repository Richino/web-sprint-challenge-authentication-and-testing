const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../users/user-models");
const tokenBuilder = require("./token-builder");
const { checkAuthPayload, checkUsernameAvailable } = require("../middleware/validation");

router.post("/register", checkAuthPayload, checkUsernameAvailable, (req, res, next) => {
	let newUser = req.body;
	console.log(newUser);
	const hashRounds = process.env.BCRYPT_ROUNDS || 8;
	const hashedPassword = bcrypt.hashSync(newUser.password, hashRounds);

	newUser.password = hashedPassword;

	User.add(newUser)
		.then((newUser) => {
			res.status(201).json(newUser);
		})
		.catch(next);
});

router.post("/login", checkAuthPayload, (req, res, next) => {
	let { username, password } = req.body;

	User.findBy({ username })
		.then(([user]) => {
			if (user && bcrypt.compareSync(password, user.password)) {
				const token = tokenBuilder(user);

				res.status(200).json({
					message: `Welcome, ${user.username}`,
					token,
				});
			} else {
				next({ status: 401, message: "invalid credentials" });
			}
		})
		.catch(next);
});

module.exports = router;
