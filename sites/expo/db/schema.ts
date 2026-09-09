import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

// Anonymous aggregate only: no email, IP address, device ID, or user agent.
export const expoInterest = sqliteTable('expo_interest', {
  day: text('day').primaryKey(),
  count: integer('count').notNull().default(0),
});
