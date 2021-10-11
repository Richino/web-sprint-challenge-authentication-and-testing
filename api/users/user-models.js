const db = require("../../data/dbConfig");

async function add(user) {
	const [id] = await db("users").insert(user);
	return findById(id);
}
function findById(id) {
	return db("users as U").select("U.id", "U.username", "U.password").where("U.id", id).first();
}

function findBy(filter) {
	return db("users as U").select("U.id", "U.username", "U.password").where(filter);
}

module.exports = {
	add,
	findBy,
	findById,
};
