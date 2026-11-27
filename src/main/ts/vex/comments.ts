/**
 * Joins the comment derived from the VEX entry with the optional comment the
 * user typed on the approve step. The user's comment goes on the next line
 * (SonarQube renders a line break in a dependency-risk comment as <br/>).
 *
 * KEEP IN SYNC WITH cli/vex-import.py (join_comments)
 */
export function joinComments(vexComment: string, userComment: string): string {
  const extra = userComment.trim();
  return extra ? `${vexComment}\n${extra}` : vexComment;
}
