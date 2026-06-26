-- Blog database schema — exercises relations, constraints, indexes, views,
-- triggers, full-text search, and generated columns.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE users (
  id        INTEGER PRIMARY KEY,
  username  TEXT NOT NULL UNIQUE,
  email     TEXT NOT NULL UNIQUE,
  created   TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (length(username) >= 3)
);

CREATE TABLE posts (
  id        INTEGER PRIMARY KEY,
  author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title     TEXT NOT NULL,
  body      TEXT NOT NULL,
  views     INTEGER NOT NULL DEFAULT 0,
  published INTEGER NOT NULL DEFAULT 0,
  created   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_posts_author ON posts(author_id);

CREATE TABLE comments (
  id        INTEGER PRIMARY KEY,
  post_id   INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body      TEXT NOT NULL,
  created   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_comments_post ON comments(post_id);

CREATE TABLE tags (
  id   INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE post_tags (
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  tag_id  INTEGER NOT NULL REFERENCES tags(id)  ON DELETE CASCADE,
  PRIMARY KEY (post_id, tag_id)
);

-- View: published posts with author + comment count.
CREATE VIEW v_post_summary AS
SELECT p.id, p.title, u.username AS author,
       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS n_comments,
       p.views
FROM posts p JOIN users u ON u.id = p.author_id
WHERE p.published = 1;

-- Trigger: maintain a denormalized per-user post count.
CREATE TABLE user_stats (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, n_posts INTEGER NOT NULL DEFAULT 0);
CREATE TRIGGER trg_post_ins AFTER INSERT ON posts BEGIN
  INSERT INTO user_stats(user_id, n_posts) VALUES (new.author_id, 1)
    ON CONFLICT(user_id) DO UPDATE SET n_posts = n_posts + 1;
END;

-- Full-text search over post titles+bodies (FTS5).
CREATE VIRTUAL TABLE post_fts USING fts5(title, body, content='posts', content_rowid='id');
CREATE TRIGGER trg_fts_ins AFTER INSERT ON posts BEGIN
  INSERT INTO post_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
END;
