import { fail, redirect } from '@sveltejs/kit';
import { setFlash } from 'sveltekit-flash-message/server';
import { setError, superValidate } from 'sveltekit-superforms/server';
import { Argon2id } from 'oslo/password';
import { lucia } from '$lib/server/lucia';
import { createUser } from '$lib/server/database/user-model';
import { userSchema } from '$lib/config/zod-schemas';
import { sendVerificationEmail } from '$lib/config/email-messages';
import { validateUniqueNickname } from '$lib/server/validation';

const signUpSchema = userSchema.pick({
	nickname: true,
	email: true,
	password: true,
	terms: true
});

export const load = async (event) => {
	if (event.locals.user) {
		redirect(302, '/dashboard');
	}
	const form = await superValidate(event, signUpSchema);
	return {
		form
	};
};

export const actions = {
	default: async (event) => {
		const form = await superValidate(event, signUpSchema);

		if (!form.valid) {
			return fail(400, {
				form
			});
		}

		// Perform server-side validation
		const isNicknameUnique = await validateUniqueNickname(form.data.nickname);
		if (!isNicknameUnique) {
			return setError(form, 'nickname', 'This nickname is already taken');
		}

		try {
			const password = await new Argon2id().hash(form.data.password);
			const id = crypto.randomUUID();
			const user = {
				id: id,
				email: form.data.email.toLowerCase(),
				nickname: form.data.nickname,
				password: password,
				role: 'USER',
				verified: true, // Set to true by default
				receiveEmail: true,
				terms: form.data.terms,
				createdAt: new Date(),
				updatedAt: new Date()
			};
			const newUser = await createUser(user);
			if (newUser) {
				const session = await lucia.createSession(newUser.id, {});
				const sessionCookie = lucia.createSessionCookie(session.id);
				event.cookies.set(sessionCookie.name, sessionCookie.value, {
					path: '.',
					...sessionCookie.attributes
				});
				setFlash(
					{
						type: 'success',
						message: 'Account created successfully. You are now logged in.'
					},
					event
				);
			}
		} catch (e) {
			console.error(e);
			setFlash({ type: 'error', message: 'Account was not able to be created.' }, event);
			if (e instanceof Error && 'code' in e) {
				if (e.code === '23505') { // PostgreSQL unique constraint violation error code
					if ('constraint' in e && e.constraint === 'users_email_unique') {
						return setError(form, 'email', 'A user with that email already exists.');
					}
				}
			}
			return setError(form, 'An unexpected error occurred.');
		}
		return { form };
	}
};
