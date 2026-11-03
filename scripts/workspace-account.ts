import '../server/env';
import { WorkspaceStore } from '../server/workspace/store';

const args = process.argv.slice(2);
const value = (flag: string) => args[args.indexOf(flag) + 1];
async function main() {
    const filename = process.env.GHOSTWIRES_WORKSPACE_DB;
    if (!filename) throw new Error('Set GHOSTWIRES_WORKSPACE_DB to the absolute database path first.');
    if (!args.includes('--email')) throw new Error('Provide --email. Use --workspace, --role and --password-stdin to create an account, or --revoke to remove one.');
    const store = new WorkspaceStore(filename, Number(process.env.GHOSTWIRES_RETENTION_DAYS || 30));
    try {
        if (args.includes('--revoke')) { store.revokeAccount(value('--email')); console.log('Account and its sessions revoked.'); return; }
        if (!args.includes('--password-stdin') || !args.includes('--workspace') || !args.includes('--role')) throw new Error('Creation requires --workspace <slug> --email <email> --role owner|analyst|viewer --password-stdin.');
        if (process.stdin.isTTY) throw new Error('Pipe a password through standard input; do not put it in command arguments. See docs/WORKSPACE.md.');
        let password = '';
        for await (const chunk of process.stdin) { password += chunk.toString(); if (password.length > 258) throw new Error('Password is too long.'); }
        password = password.replace(/\r?\n$/, '');
        await store.createAccount(value('--workspace'), value('--email'), password, value('--role') as any);
        password = '';
        console.log('Workspace account created. No password was logged.');
    } finally { store.close(); }
}
main().catch(e => { console.error((e as Error).message); process.exitCode = 1; });
