import { getUserByNickname } from './database/user-model';

export async function validateUniqueNickname(nickname: string): Promise<boolean> {
    const user = await getUserByNickname(nickname);
    return user === null;
}