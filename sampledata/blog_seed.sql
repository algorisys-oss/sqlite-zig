PRAGMA foreign_keys = ON;
INSERT INTO users(username,email) VALUES
 ('alice','alice@example.com'),('bob','bob@example.com'),('carol','carol@example.com');

INSERT INTO posts(author_id,title,body,views,published) VALUES
 (1,'Intro to Zig','Zig is a systems language with comptime and no hidden control flow.',1200,1),
 (1,'Porting SQLite','We migrate SQLite from C to Zig module by module, keeping the C ABI.',3400,1),
 (2,'Why WAL mode','Write-ahead logging improves concurrency for readers and writers.',870,1),
 (2,'Draft: ideas','Some half-baked notes, not ready.',5,0),
 (3,'Full-text search','FTS5 lets you MATCH documents ranked by relevance.',640,1);

INSERT INTO tags(name) VALUES ('zig'),('sqlite'),('database'),('performance');
INSERT INTO post_tags VALUES (1,1),(2,1),(2,2),(3,2),(3,3),(3,4),(5,2),(5,3);

INSERT INTO comments(post_id,user_id,body) VALUES
 (2,2,'Great write-up on the ABI boundary!'),
 (2,3,'Does the page cache still pass the corruption tests?'),
 (2,1,'Yes — pcache is ported and pager1 is green.'),
 (1,3,'comptime is the killer feature.'),
 (3,1,'WAL + busy_timeout solved our contention.');
