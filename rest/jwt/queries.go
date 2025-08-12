package jwt

const QueryJwtByJti string = "select j.user_id, u.enabled " +
	"FROM app_jwt_access_token j " +
	"INNER JOIN app_users as u ON j.user_id=u.id " +
	"where j.token_id=? AND j.enabled=1"

const QueryAdminJwtByJti string = "select j.admin_id, a.enabled " +
	"FROM jwt_access_token j " +
	"INNER JOIN admins as a ON j.admin_id=a.id " +
	"where j.token_id=?"
