export interface GithubUser {
    login?: string;
    name?: string;
    email?: string;
    public_repos?: number;
    total_private_repos?: number;
    followers?: number;
    message?: string;
}
export interface GithubRepo {
    name?: string;
    full_name?: string;
    private?: boolean;
    owner?: {
        login?: string;
    };
}
export declare function githubIdentity(user: GithubUser, repos?: GithubRepo[]): string;
export declare function githubRepoCounts(user: GithubUser, repos: GithubRepo[]): {
    publicRepos: number;
    privateRepos: number;
};
export declare function githubRecentNames(repos: GithubRepo[], max?: number): string;
export declare function githubCardMeta(user: GithubUser, scopes: string, repos?: GithubRepo[]): Record<string, string>;
