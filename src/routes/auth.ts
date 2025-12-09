import { Router, Request, Response } from "express";
import { UserService } from "../services/user-service";

const authRoutes = Router();
const userService = new UserService();

authRoutes.post("/login", async (req: Request, res: Response) => {
	const { username, password } = req.body;
	if (!username || !password) return res.status(400).json({ message: "Credenciais faltando" });

	try {
		const user = await userService.getUserByUsername(username);
		if (!user) return res.status(401).json({ message: "Username ou senha inválidos" });

		const isValidPassword = await userService.validatePassword(password, user.password);
		if (!isValidPassword) return res.status(401).json({ message: "Username ou senha inválidos" });

		// Regenerar sessão para mitigar session fixation
		req.session.regenerate((err) => {
			if (err) return res.status(500).json({ message: "Erro ao criar sessão" });

			req.session.user = {
				id: user.id,
				username: user.username,
				role: user.role
			};
			req.session.save((err2) => {
				if (err2) return res.status(500).json({ message: "Erro ao salvar sessão" });
				// retornar usuário sem senha
				const { password: _, ...safeUser } = user;
				return res.json({ user: safeUser });
			});
		});
	} catch (err) {
		console.error(err);
		return res.status(500).json({ message: "Erro no servidor" });
	}
});

authRoutes.post("/logout", (req: Request, res: Response) => {
	req.session.destroy((err) => {
		if (err) return res.status(500).json({ message: "Erro ao encerrar sessão" });
		// limpar cookie padrão do express-session
		res.clearCookie("connect.sid");
		return res.json({ message: "Deslogado" });
	});
});

export default authRoutes;