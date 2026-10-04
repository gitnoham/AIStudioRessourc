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
  owner?: { login?: string };
}

function repoOwner(repo: GithubRepo): string {
  const fromOwner = repo.owner?.login?.trim() ?? "";
  if (fromOwner) return fromOwner;
  const full = repo.full_name?.trim() ?? "";
  const slash = full.indexOf("/");
  return slash > 0 ? full.slice(0, slash) : "";
}

export function githubIdentity(user: GithubUser, repos: GithubRepo[] = []): string {
  const login = user.login?.trim() || repos.map(repoOwner).find(Boolean) || "";
  if (!login) return "?";
  const name = user.name?.trim();
  let identity = name ? `${login} (${name})` : login;
  if (user.email?.trim()) identity += ` | ${user.email.trim()}`;
  return identity;
}

export function githubRepoCounts(user: GithubUser, repos: GithubRepo[]): { publicRepos: number; privateRepos: number } {
  const listedPub = repos.filter((r) => !r.private).length;
  const listedPriv = repos.filter((r) => r.private).length;
  return {
    publicRepos: Math.max(user.public_repos ?? 0, listedPub),
    privateRepos: Math.max(user.total_private_repos ?? 0, listedPriv),
  };
}

export function githubRecentNames(repos: GithubRepo[], max = 10): string {
  const names = repos.slice(0, max).map((r) => {
    const name = r.name?.trim() || r.full_name?.split("/")[1] || "?";
    return `${name}${r.private ? " 🔒" : ""}`;
  });
  if (!names.length) return "";
  const extra = repos.length > max ? ` (+${repos.length - max})` : "";
  return names.join(", ") + extra;
}

export function githubCardMeta(
  user: GithubUser,
  scopes: string,
  repos: GithubRepo[] = [],
): Record<string, string> {
  const identity = githubIdentity(user, repos);
  const { publicRepos, privateRepos } = githubRepoCounts(user, repos);
  const recent = githubRecentNames(repos);
  return {
    identity,
    publicRepos: String(publicRepos),
    privateRepos: String(privateRepos),
    followers: String(user.followers ?? 0),
    scopes: scopes.trim() || "N/A",
    ...(recent ? { recentRepos: recent } : {}),
  };
}
