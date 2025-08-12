package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/bitsbuster/utils/database"
	"github.com/bitsbuster/utils/log"
	"github.com/bitsbuster/utils/types"
	"github.com/form3tech-oss/jwt-go"
	"github.com/segmentio/ksuid"
)

const (
	ERROR_TOKEN_DISABLED = "ERROR_TOKEN_DISABLED"
	ERROR_USER_DISABLED  = "ERROR_USER_DISABLED"
)

var (
	verifyKey   *rsa.PublicKey
	signKey     *rsa.PrivateKey
	db          *database.DbPool
	validateUrl *string
)

type DBTokenValidator func(jti string) (*DBTokenValidatorResult, error)

type DBTokenValidatorResult struct {
	UserID       types.SqlUuid
	PlanID       *uint64
	Enabled      bool
	TokenEnabled bool
}
type JwtProps struct {
	PrivateKey   *[]byte
	PublicKey    *[]byte
	DbConnection *database.DbPool
	ValidateUrl  *string
	LogLevel     log.LogLevelValue
}

func (j *JwtProps) Setup() {
	var err error
	if j.PrivateKey != nil {
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(*j.PrivateKey)
		fatal(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(*j.PublicKey)
	if err != nil {
		log.Errorf(nil, "JWT Verification key is required, please check Public Key is present and it is well formed: %+v", err)

		panic(err)
	}

	if j.DbConnection == nil && j.ValidateUrl == nil {
		log.Errorln(nil, "Database connection or api request to validate token is required")
		panic("Database connection or api request to validate token is required")
	}
	if j.DbConnection != nil {
		db = j.DbConnection
	}
	if j.ValidateUrl != nil {
		_, err := url.ParseRequestURI(*j.ValidateUrl)
		if err != nil {
			log.Errorf(nil, "Invalid validation url. {%s}", err.Error())
			panic("Invalid validation url.")
		}
		validateUrl = j.ValidateUrl
	}

	log.LogLevel = j.LogLevel

}

// CustomerInfo Define some custom types were going to use within our tokens
type CustomerInfo struct {
	ID         string       `json:"id"`
	Username   string       `json:"username,omitempty"`
	CustomerID interface{}  `json:"cid,omitempty"`
	Roles      *[]uint16    `json:"sku,omitempty"`
	CustomData *interface{} `json:"customData,omitempty"`
}

// Checks if CustomerInfo object contains any RoleServicesInfo with the
func (c *CustomerInfo) ContainsRoleID(roleID uint16) bool {
	for _, roleService := range *c.Roles {
		if roleService == roleID {
			return true
		}
	}
	return false
}

type CustomClaims struct {
	*jwt.StandardClaims
	TokenType string `json:"type,omitempty"`
	CustomerInfo
	Address   string  `json:"address,omitempty"`
	UserAgent *string `json:"userAgent,omitempty"`
}

func SetupJWT(privateKeyFile, publicKeyFile string) {
	signBytes, err := os.ReadFile(privateKeyFile)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := os.ReadFile(publicKeyFile)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)

}

func fatal(err error) {
	if err != nil {
		panic(err)
	}
}

// Creates a new Token
func CreateToken(user string, customerID interface{}, expires uint64, roles *[]uint16) (*string, *CustomClaims, error) {
	return CreateTokenWithResource(user, customerID, expires, nil, roles, "")
}

// Creates a new Token with resource
//
//	Output
//		The token
//		The Custom Claims struct
//		The error in case any error raises
func CreateTokenWithResource(user string, customerID interface{}, expires uint64, userAgent *string, roles *[]uint16, resource string) (*string, *CustomClaims, error) {
	if signKey == nil {
		return nil, nil, errors.New("no sign key has been set to create JWT")
	}
	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	// set our claims
	jti := ksuid.New().String()
	claims := jwt.StandardClaims{Id: jti}
	if expires > 0 {

		claims.ExpiresAt = time.Now().Add(time.Minute * time.Duration(expires)).Unix()
	}
	c := CustomerInfo{
		Username:   user,
		CustomerID: customerID,
		Roles:      roles,
	}

	customClaims := &CustomClaims{
		&claims,
		"erp",
		c,
		"",
		userAgent,
	}

	t.Claims = customClaims

	// Create token string
	token, err := t.SignedString(signKey)
	if err != nil {
		return nil, nil, err
	}
	return &token, customClaims, nil
}

func VerifyToken(dbTokenValidator DBTokenValidator, tokenString *string) (*CustomerInfo, *types.SqlUuid, error) {
	return VerifyTokenWityIP(dbTokenValidator, tokenString, "")
}

func VerifyTokenWityIP(dbTokenValidator DBTokenValidator, tokenString *string, ip string) (*CustomerInfo, *types.SqlUuid, error) {

	var validatorResult *DBTokenValidatorResult
	// Parse the token
	token, err := jwt.ParseWithClaims(*tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return verifyKey, nil
	})

	if err != nil {
		fmt.Println(err.Error())
		return nil, nil, err
	}

	claims := token.Claims.(*CustomClaims)
	//fmt.Println(claims.CustomerInfo.Username)
	c := claims.CustomerInfo

	if len(claims.Address) > 0 && claims.Address != ip {
		log.Errorf(nil, "Token bound ip is %s, but remote ip is %s", claims.Address, ip)
		return nil, nil, errors.New("ERROR_INVALID_JWT_BOUND_IP")
	}
	if db != nil {
		validatorResult, err = dbTokenValidator(claims.Id)
	}

	if err != nil {
		log.Errorf(nil, "Token %s is disabled for user %s", claims.Id, c.Username)
		return nil, nil, errors.New("jwt is disabled")
	} else if !validatorResult.TokenEnabled {
		log.Errorf(nil, "token {%s} is disabled", claims.Id)
		return nil, nil, errors.New(ERROR_TOKEN_DISABLED)
	} else if !validatorResult.Enabled {
		log.Errorf(nil, "user %s is disabled", c.Username)
		return nil, nil, errors.New(ERROR_USER_DISABLED)

	}

	c.ID = claims.Id

	return &c, &validatorResult.UserID, nil
}

func Encrypt(raw string) *string {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		verifyKey,
		[]byte(raw),
		nil)
	if err != nil {
		panic(err)
	}
	encoded := b64.StdEncoding.EncodeToString(encryptedBytes)
	//fmt.Println("encrypted bytes: ", encoded)
	return &encoded
}

func Decrypt(encrypted *string) error {
	encryptedBytes, err := b64.StdEncoding.DecodeString(*encrypted)
	if err != nil {
		return err
	}

	decryptedBytes, err := signKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}
	*encrypted = string(decryptedBytes)
	return nil
}

// Validates the token against the database. Returns user id, if the token is enabled and the err if it fails
func ValidateTokenAtDB(jti string) (types.SqlUuid, bool, error) {

	var userID types.SqlUuid
	var enabled bool

	log.Debugln(nil, "ValidateTokenAtDB: Validating token %s", jti)
	row := db.GetConnection().QueryRow(QueryJwtByJti, jti)

	err := row.Scan(&userID, &enabled)

	if err != nil {
		serr := database.GetSqlError(err)
		log.Errorf(nil, "ValidateTokenAtDB: error getting jti information from database: %+v", serr)
		return types.SqlUuid{}, false, serr
	}
	return userID, enabled, nil

}
