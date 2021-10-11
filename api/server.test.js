const request = require("supertest");
const server = require("./server");
const db = require("../data/dbConfig");
const User = require("./users/user-models");

beforeAll(async () => {
	await db.migrate.rollback();
	await db.migrate.latest();
});

afterAll(async () => {
	await db.destroy();
});

test("sanity", () => {
	expect(true).toBe(true);
});

describe("[POST] /auth/register", () => {
	it("adds a user and returns it", async () => {
		await request(server).post("/api/auth/register").send({
			username: "billiam",
			password: "secret",
		});
		expect(
			await User.findBy({
				username: "billiam",
			})
		).toHaveLength(1);
	});

	it("returns error if username is already taken", async () => {
		const res = await request(server).post("/api/auth/register").send({
			username: "billiam",
		});
		expect(res.body).toMatchObject({ message: "username taken" });
	});
});

describe("[POST] /auth/login", () => {
	it("on successful login returns username and token", async () => {
		await request(server).post("/api/auth/login").send({
			username: "billiam",
			password: "secret",
		});
		expect.objectContaining({ token: expect.toBeDefined });
	});

	it("returns error when credentials are missing", async () => {
		const res = await request(server).post("/api/auth/login").send({
			username: "",
			password: "",
		});
		expect(res.body).toMatchObject({
			message: "username and password required",
		});
	});
});
