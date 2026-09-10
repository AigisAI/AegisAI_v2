# AegisAI EXPO mobile experience

Sample-only exhibition experience, separate from the production scanner platform. The user authorized publishing both variants under the existing product domain through GitHub CI/CD. `/` and `/compare` show design comparisons. `/expo1` opens version A; `/expo2` opens the independently designed version B. `/stitch`, `/expo`, and `/direct` remain local preview aliases. The existing product demo remains at https://aegisai.tailaca7d2.ts.net/.

The experience uses fictional order data and a fixed SQL-injection teaching example. It does not scan repositories, run customer code, perform attacks, or call an AI model. Suggested changes remain advisory and do not assert a complete security review.

Anonymous interest is stored only as a daily aggregate in the `expo_interest` table: D1 for Sites preview, persistent SQLite for the existing-server deployment. No contacts or visitor identifiers are stored. An HttpOnly same-site cookie prevents ordinary repeat votes for 30 days; totals measure expressions of interest, not verified unique people. There is no public endpoint to read the aggregate. The owner can inspect the deployment database on the server; local Sites storage is separate. No account registration or pilot application is implied.

Development: `corepack pnpm dev`. Validation: `corepack pnpm lint`, `corepack pnpm exec tsc --noEmit`, `corepack pnpm test`, `corepack pnpm build`. Database migrations: `corepack pnpm db:generate`.

This standalone Site uses its own package workspace and source repository so publishing never includes unrelated changes in the parent AegisAI checkout.


`/expo3` is the third, independently designed exhibition experience: a three-question security quiz with explanations and a learning recap. Its source is `app/sense-experience.tsx`, with local Vinext routing and the same standalone deployment adapter. It shares the existing anonymous interest aggregate with the other variants.
