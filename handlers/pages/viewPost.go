package pages

import (
	"database/sql"
	"fmt"
	"forum/handlers"
	"forum/structs"
	"net/http"
	"strconv"
)

func ViewPostHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the postID from the URL parameters
		postID := r.URL.Query().Get("id")
		react := r.URL.Query().Get("react")
		like := r.URL.Query().Get("like")

		// Check if it's a reaction to the post
		if react != "" {
			if react == "0" {
				// Check if the user has already liked/disliked the post
				reactionExists, wasLike, err := checkReactionExists(db, postID, r, true)
				if err != nil {
					http.Error(w, "Failed to check reaction existence", http.StatusInternalServerError)
					return
				}

				if !reactionExists {
					// User has not reacted to the post, allow like/dislike action
					if like == "true" {
						// Update the like count for the post
						updatePostQuery := "UPDATE posts SET likes = likes + 1 WHERE postID = ?"
						_, err := db.Exec(updatePostQuery, postID)
						if err != nil {
							http.Error(w, "Failed to update post", http.StatusInternalServerError)
							return
						}
					} else if like == "false" {
						// Update the dislike count for the post
						updatePostQuery := "UPDATE posts SET dislikes = dislikes + 1 WHERE postID = ?"
						_, err := db.Exec(updatePostQuery, postID)
						if err != nil {
							http.Error(w, "Failed to update post", http.StatusInternalServerError)
							return
						}
					}

					// Store the user's reaction to the post
					user := handlers.IsLoggedIn(r, db).User
					err = storePostReaction(db, postID, user.ID, like == "true")
					if err != nil {
						http.Error(w, "Failed to store reaction", http.StatusInternalServerError)
						return
					}
				} else {
					// Update the like and dislike count for the post
					updatePostQuery := "UPDATE posts SET likes = likes + ?, dislikes = dislikes + ? WHERE postID = ?"
					var (
						likeIncrement    int
						dislikeIncrement int
					)

					if (like == "true" && !wasLike) || (like == "false" && wasLike) {
						if like == "true" && !wasLike {
							likeIncrement = 1
							dislikeIncrement = -1
						} else if like == "false" && wasLike {
							likeIncrement = -1
							dislikeIncrement = 1
						}

						user := handlers.IsLoggedIn(r, db).User

						// Update the reaction_type to false for the specified post and user
						updateQuery := "UPDATE post_reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?"
						_, err = db.Exec(updateQuery, like == "true", postID, user.ID)
						if err != nil {
							http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
							return
						}
					} else {
						if like == "true" {
							likeIncrement = -1
							dislikeIncrement = 0
						} else {
							likeIncrement = 0
							dislikeIncrement = -1
						}

						user := handlers.IsLoggedIn(r, db).User

						// Delete the row from post_reactions table for the specified post and user
						deleteQuery := "DELETE FROM post_reactions WHERE post_id = ? AND user_id = ?"
						_, err := db.Exec(deleteQuery, postID, user.ID)
						if err != nil {
							http.Error(w, "Failed to delete reaction", http.StatusInternalServerError)
							return
						}
					}

					_, err := db.Exec(updatePostQuery, likeIncrement, dislikeIncrement, postID)
					if err != nil {
						http.Error(w, "Failed to update post", http.StatusInternalServerError)
						return
					}
				}
			} else {
				// It's a reaction to a comment
				// Convert the react value to an integer
				commentID, err := strconv.Atoi(react)
				if err != nil {
					http.Error(w, "Invalid comment ID", http.StatusBadRequest)
					return
				}

				// Check if the user has already liked/disliked the comment
				reactionExists, wasLike, err := checkReactionExists(db, strconv.Itoa(commentID), r, false)
				if err != nil {
					http.Error(w, "Failed to check reaction existence", http.StatusInternalServerError)
					return
				}

				if !reactionExists {
					// User has not reacted to the comment, allow like/dislike action
					if like == "true" {
						// Update the like count for the comment
						updateCommentQuery := "UPDATE comments SET likes = likes + 1 WHERE commentID = ?"
						_, err := db.Exec(updateCommentQuery, commentID)
						if err != nil {
							http.Error(w, "Failed to update comment", http.StatusInternalServerError)
							return
						}
					} else if like == "false" {
						// Update the dislike count for the comment
						updateCommentQuery := "UPDATE comments SET dislikes = dislikes + 1 WHERE commentID = ?"
						_, err := db.Exec(updateCommentQuery, commentID)
						if err != nil {
							http.Error(w, "Failed to update comment", http.StatusInternalServerError)
							return
						}
					}

					// Store the user's reaction to the comment
					user := handlers.IsLoggedIn(r, db).User
					err = storeCommentReaction(db, commentID, user.ID, like == "true")
					if err != nil {
						http.Error(w, "Failed to store reaction", http.StatusInternalServerError)
						return
					}
				} else {
					// Update the like and dislike count for the post
					updateCommentQuery := "UPDATE comments SET likes = likes + ?, dislikes = dislikes + ? WHERE commentID = ?"
					var (
						likeIncrement    int
						dislikeIncrement int
					)

					if (like == "true" && !wasLike) || (like == "false" && wasLike) {
						if like == "true" && !wasLike {
							likeIncrement = 1
							dislikeIncrement = -1
						} else if like == "false" && wasLike {
							likeIncrement = -1
							dislikeIncrement = 1
						}

						user := handlers.IsLoggedIn(r, db).User

						// Update the reaction_type to false for the specified post and user
						updateQuery := "UPDATE comment_reactions SET reaction_type = ? WHERE comment_id = ? AND user_id = ?"
						_, err = db.Exec(updateQuery, like == "true", commentID, user.ID)
						if err != nil {
							http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
							return
						}
					} else {
						if like == "true" {
							likeIncrement = -1
							dislikeIncrement = 0
						} else {
							likeIncrement = 0
							dislikeIncrement = -1
						}

						user := handlers.IsLoggedIn(r, db).User

						// Delete the row from comment_reactions table for the specified comment and user
						deleteQuery := "DELETE FROM comment_reactions WHERE comment_id = ? AND user_id = ?"
						_, err := db.Exec(deleteQuery, commentID, user.ID)
						if err != nil {
							http.Error(w, "Failed to delete reaction", http.StatusInternalServerError)
							return
						}
					}

					_, err := db.Exec(updateCommentQuery, likeIncrement, dislikeIncrement, commentID)
					if err != nil {
						http.Error(w, "Failed to update post", http.StatusInternalServerError)
						return
					}
				}
			}
		}

		// Query the database to get the post information
		postQuery := `
			SELECT postID, title, description, imageFileName, creationDate, username, likes, dislikes
			FROM posts
			WHERE postID = ?
		`

		postRow := db.QueryRow(postQuery, postID)

		var post structs.Post
		var imageFileName sql.NullString
		err := postRow.Scan(&post.ID, &post.Title, &post.Description, &imageFileName, &post.CreationDate, &post.Username, &post.Likes, &post.Dislikes)
		if err != nil {
			http.Error(w, "Failed to retrieve post", http.StatusInternalServerError)
			return
		}

		if imageFileName.Valid {
			post.ImageFileName = imageFileName.String
		} else {
			post.ImageFileName = "" // Set a default value for imageFileName when it is NULL
		}

		// Query the database to get the comments for the post
		commentQuery := `
			SELECT commentID, content, creationDate, username, likes, dislikes
			FROM comments
			WHERE postID = ?
			ORDER BY creationDate ASC
		`

		commentRows, err := db.Query(commentQuery, postID)
		if err != nil {
			http.Error(w, "Failed to retrieve comments", http.StatusInternalServerError)
			return
		}
		defer commentRows.Close()

		comments := []structs.Comment{}
		for commentRows.Next() {
			var comment structs.Comment
			err := commentRows.Scan(&comment.ID, &comment.Content, &comment.CreationDate, &comment.Username, &comment.Likes, &comment.Dislikes)
			if err != nil {
				http.Error(w, "Failed to scan comment rows", http.StatusInternalServerError)
				return
			}
			comments = append(comments, comment)
		}

		if err = commentRows.Err(); err != nil {
			http.Error(w, "Failed to iterate over comment rows", http.StatusInternalServerError)
			return
		}

		// Create a data struct to pass to the template
		data := struct {
			structs.User
			Post     structs.Post
			Comments []structs.Comment
		}{
			User:     handlers.IsLoggedIn(r, db).User,
			Post:     post,
			Comments: comments,
		}

		// Render the template with the data
		handlers.RenderTemplates("viewPost", data, w, r)
	}
}

func checkReactionExists(db *sql.DB, reactionID string, r *http.Request, isPost bool) (bool, bool, error) {
	user := handlers.IsLoggedIn(r, db).User

	// Determine the table name and column names based on whether it's a post or comment reaction
	tableName := "post_reactions"
	idColumnName := "post_id"
	userIDColumnName := "user_id"
	if !isPost {
		tableName = "comment_reactions"
		idColumnName = "comment_id"
	}

	// Query the database to check if the user has already reacted to the post or comment
	query := fmt.Sprintf(
		"SELECT EXISTS (SELECT 1 FROM %s WHERE %s = ? AND %s = ?), reaction_type FROM %s WHERE %s = ? AND %s = ?",
		tableName, idColumnName, userIDColumnName, tableName, idColumnName, userIDColumnName,
	)

	row := db.QueryRow(query, reactionID, user.ID, reactionID, user.ID)

	var exists bool
	var reactionType bool
	err := row.Scan(&exists, &reactionType)
	if err != nil {
		if err == sql.ErrNoRows {
			// No rows found, indicating the reaction doesn't exist
			return false, false, nil
		}
		return false, false, err
	}

	return exists, reactionType, nil
}

func storePostReaction(db *sql.DB, postID string, userUUID string, reactionType bool) error {
	insertPostReactionQuery := `
		INSERT INTO post_reactions (post_id, user_id, reaction_type)
		VALUES (?, ?, ?)
	`
	_, err := db.Exec(insertPostReactionQuery, postID, userUUID, reactionType)
	if err != nil {
		return err
	}
	return nil
}

func storeCommentReaction(db *sql.DB, commentID int, userUUID string, reactionType bool) error {
	insertCommentReactionQuery := `
		INSERT INTO comment_reactions (comment_id, user_id, reaction_type)
		VALUES (?, ?, ?)
	`
	_, err := db.Exec(insertCommentReactionQuery, commentID, userUUID, reactionType)
	if err != nil {
		return err
	}
	return nil
}
