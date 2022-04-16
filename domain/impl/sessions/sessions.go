package sessions

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/base32"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/travelata/auth/config"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	authPb "github.com/travelata/auth/proto"
	"github.com/travelata/kit"
	"github.com/travelata/kit/log"
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"math/rand"
	"time"
)

type sessionImpl struct {
	userService     domain.UserService
	securityService domain.SecurityService
	authCfg         *config.Auth
	sessionStorage  domain.SessionStorage
	authCodeStorage domain.AuthCodeStorage
}

func NewSessionService(userService domain.UserService,
	securityService domain.SecurityService,
	authCfg *config.Auth,
	sessionStorage domain.SessionStorage,
	authCodeStorage domain.AuthCodeStorage) domain.SessionsService {
	return &sessionImpl{
		userService:     userService,
		securityService: securityService,
		authCfg:         authCfg,
		sessionStorage:  sessionStorage,
		authCodeStorage: authCodeStorage,
	}
}

func (s *sessionImpl) l() log.CLogger {
	return logger.L().Cmp("sessions-service")
}

func (s *sessionImpl) createJwtToken(ctx context.Context, sess *domain.Session) (*domain.SessionToken, error) {

	s.l().C(ctx).Mth("create-jwt").F(log.FF{"uid": sess.UserId}).Dbg()

	st := &domain.SessionToken{
		SessionId: sess.Id,
	}

	now := kit.Now()

	// access token
	atExpireAt := now.Add(time.Second * time.Duration(s.authCfg.AccessToken.ExpirationPeriodSec))
	atClaims := jwt.MapClaims{}
	atClaims["tid"] = kit.NewId()
	atClaims["exp"] = atExpireAt.Unix()
	atClaims["sid"] = sess.Id
	atClaims["uid"] = sess.UserId
	atClaims["un"] = sess.Username
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	atStr, err := at.SignedString([]byte(s.authCfg.AccessToken.Secret))
	if err != nil {
		return nil, errors.ErrAccessTokenCreation(err, ctx)
	}

	// refresh token
	rtExpireAt := now.Add(time.Second * time.Duration(s.authCfg.RefreshToken.ExpirationPeriodSec))
	rtClaims := jwt.MapClaims{}
	rtClaims["tid"] = kit.NewId()
	rtClaims["exp"] = rtExpireAt.Unix()
	rtClaims["sid"] = sess.Id
	rtClaims["uid"] = sess.UserId
	rtClaims["un"] = sess.Username
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	rtStr, err := rt.SignedString([]byte(s.authCfg.RefreshToken.Secret))
	if err != nil {
		return nil, errors.ErrAccessTokenCreation(err, ctx)
	}

	st.AccessToken = atStr
	st.AccessTokenExpiresAt = atExpireAt

	st.RefreshToken = rtStr
	st.RefreshTokenExpiresAt = rtExpireAt

	return st, nil

}

func (s *sessionImpl) createSession(ctx context.Context, usr *domain.User) (*domain.Session, *domain.SessionToken, error) {
	l := s.l().C(ctx).Mth("create-session").F(log.FF{"user": usr.Username}).Dbg()

	// get user roles (given by groups and explicit)
	roles, err := s.securityService.GetRolesForGroups(ctx, usr.Details.Groups)
	if err != nil {
		return nil, nil, err
	}

	// add explicit roles
	roles = append(roles, usr.Details.Roles...)

	// check at least one role exists
	if len(roles) == 0 {
		return nil, nil, errors.ErrSessionNoRolesGranted(ctx)
	}

	// create a new session
	now := kit.Now()
	session := &domain.Session{
		Id:             kit.NewId(),
		UserId:         usr.Id,
		Username:       usr.Username,
		LoginAt:        now,
		LastActivityAt: now,
		Details: &domain.SessionDetails{
			Roles: roles,
		},
	}

	// create JWT
	token, err := s.createJwtToken(ctx, session)
	if err != nil {
		return nil, nil, err
	}

	// save session to store
	if err := s.sessionStorage.CreateSession(ctx, session, token); err != nil {
		return nil, nil, err
	}

	l.F(log.FF{"sid": session.Id}).Dbg("ok")

	return session, token, nil
}

func (s *sessionImpl) checkUserPassword(ctx context.Context, rq *domain.LoginPasswordRequest) (*domain.User, error) {
	l := s.l().C(ctx).Mth("check-user-password").F(log.FF{"user": rq.Username}).Dbg()

	// get user by username
	found, usr, err := s.userService.GetByUsername(ctx, rq.Username)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrSessionNoUserFound(ctx, rq.Username)
	}

	// check user status
	if usr.Status != authPb.USER_STATUS_ACTIVE {
		return nil, errors.ErrSessionUserNotActiveStatus(ctx)
	}

	// check auth type
	if usr.AuthType != domain.AuthTypePassword {
		return nil, errors.ErrSessionAuthMethodDoesntAllowLogin(ctx, usr.Id)
	}

	// check password
	err = bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(rq.Password))
	if err != nil {
		return nil, errors.ErrSessionPasswordValidation(ctx)
	}

	l.Dbg("password validation passed")

	return usr, nil
}

func (s *sessionImpl) generateAuthCode() string {
	// if mock code is specified in config, use it
	// otherwise generate a code
	if s.authCfg.SecretCode.Mock == "" {
		nBig, _ := cryptoRand.Int(cryptoRand.Reader, big.NewInt(10000))
		return fmt.Sprintf("%04d", nBig.Int64())
	} else {
		return s.authCfg.SecretCode.Mock
	}
}

func (s *sessionImpl) createLoginToken() string {
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	return base32.StdEncoding.EncodeToString(randomBytes)
}

func (s *sessionImpl) SendAuthCode(ctx context.Context, rq *domain.SendAuthCodeRequest) (*domain.SendAuthCodeResponse, error) {
	l := s.l().C(ctx).Mth("send-auth-code").F(log.FF{"username": rq.Username}).Dbg()

	// check username is a valid phone
	if rq.Username == "" {
		return nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}

	found, _, err := s.userService.GetByUsername(ctx, rq.Username)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}

	// generate code
	authCode := &domain.AuthCode{
		Username:  rq.Username,
		Code:      s.generateAuthCode(),
		ExpiresAt: kit.Now().Add(time.Second * time.Duration(s.authCfg.SecretCode.ExpirationPeriodSec)),
		// generate login token
		LoginToken: s.createLoginToken(),
	}

	// set to store
	if err := s.authCodeStorage.Set(ctx, authCode); err != nil {
		return nil, err
	}

	//// send sms
	//err := s.smsRepository.Send(ctx, &smsPb.SmsRequest{
	//	Phone:                authCode.Phone,
	//	Text:                 authCode.Code,
	//	DeliveryConfirmation: true,
	//})

	l.Dbg("ok")

	return &domain.SendAuthCodeResponse{LoginToken: authCode.LoginToken}, nil
}

func (s *sessionImpl) LoginPassword(ctx context.Context, rq *domain.LoginPasswordRequest) (*domain.Session, *domain.SessionToken, error) {
	s.l().C(ctx).Mth("login-password").F(log.FF{"user": rq.Username}).Dbg()
	usr, err := s.checkUserPassword(ctx, rq)
	if err != nil {
		return nil, nil, err
	}
	return s.createSession(ctx, usr)
}

func (s *sessionImpl) LoginAuthCode(ctx context.Context, rq *domain.LoginAuthCodeRequest) (*domain.Session, *domain.SessionToken, error) {
	l := s.l().C(ctx).Mth("login-auth-code").F(log.FF{"usernmame": rq.Username}).Dbg()

	// in case of any error we return the only LoginInvalid error not to reveal a real reason of login fail
	// along with we log a real error reason

	// check username is a valid phone
	if rq.Username == "" {
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}

	if rq.AuthCode == "" {
		l.E(errors.ErrSessionAuthCodeNotProvided(ctx)).Err()
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}

	// get auth code from the storage and check
	found, authCode, err := s.authCodeStorage.Get(ctx, rq.Username)
	if err != nil {
		l.E(err).Err()
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}
	// code not found
	if !found {
		l.E(errors.ErrSessionAuthCodeNotFound(ctx)).Err()
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}
	// check token
	if authCode.LoginToken != rq.LoginToken {
		l.E(errors.ErrSessionAuthLoginTokenInvalid(ctx)).Err()
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}

	// code found but somehow it before expires (this case shouldn't hit cause we rely on Redis expiration time)
	if authCode.ExpiresAt.Before(kit.Now()) {
		l.E(errors.ErrSessionAuthCodeExpired(ctx)).Err()
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}
	// wrong code
	if rq.AuthCode != authCode.Code {
		l.E(errors.ErrSessionAuthCodeWrong(ctx)).Err()
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}
	l.Dbg("code validation passed")

	// get user by username
	found, usr, err := s.userService.GetByUsername(ctx, rq.Username)
	if err != nil {
		return nil, nil, err
	}

	// if user not found, create and activate it
	if !found {
		return nil, nil, errors.ErrAuthUserLoginFail(ctx, rq.Username)
	}

	// create session
	return s.createSession(ctx, usr)
}

func (s *sessionImpl) Logout(ctx context.Context, sid string) error {
	l := s.l().C(ctx).Mth("logout").F(log.FF{"sid": sid}).Dbg()

	// find user sessions
	found, ss, err := s.sessionStorage.Get(ctx, sid)
	if err != nil {
		return err
	}
	if !found {
		l.Warn("no sessions found")
		return nil
	}
	l.F(log.FF{"uid": ss.UserId})

	// check session is already logged out
	if ss.LogoutAt != nil {
		return errors.ErrSessionLoggedOut(ctx)
	}

	// mark session as logged out
	if err := s.sessionStorage.Logout(ctx, sid, kit.Now()); err != nil {
		return err
	}
	l.Dbg("logged out")

	return nil
}

func (s *sessionImpl) verifyJwtToken(ctx context.Context, tokenStr string, secret string) (*jwt.Token, jwt.MapClaims, error) {

	// parse JWT token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.ErrSessionAuthWrongSigningMethod(ctx)
		}
		return []byte(secret), nil
	})
	if err != nil {
		if jwtErr, ok := err.(*jwt.ValidationError); ok {
			if jwtErr.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, nil, errors.ErrSessionAuthTokenExpired(ctx)
			}
		}
		return nil, nil, errors.ErrSessionAuthTokenInvalid(ctx)
	}
	if !token.Valid {
		return nil, nil, errors.ErrSessionAuthTokenInvalid(ctx)
	}

	if err := token.Claims.Valid(); err != nil {
		return nil, nil, errors.ErrSessionAuthTokenClaimsInvalid(ctx)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, errors.ErrSessionAuthTokenClaimsInvalid(ctx)
	}

	return token, claims, nil
}

func (s *sessionImpl) AuthSession(ctx context.Context, token string) (*domain.Session, error) {
	l := s.l().C(ctx).Mth("auth").Dbg()

	// verify JWT token
	_, claims, err := s.verifyJwtToken(ctx, token, s.authCfg.AccessToken.Secret)
	if err != nil {
		return nil, err
	}

	// extract SID from claims
	sid := claims["sid"].(string)
	l.F(log.FF{"sid": sid})

	// get token by sid
	found, session, err := s.sessionStorage.Get(ctx, sid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrSessionTokenInvalid(ctx)
	}

	l.F(log.FF{"uid": session.UserId})

	// check session is logged out
	if session.LogoutAt != nil {
		return nil, errors.ErrSessionLoggedOut(ctx)
	}

	l.Dbg("ok")

	// update session's last activity asynchronously
	// we have to invent another way of updating to avoid too many DB hits (maybe periodic async cron)
	//go func() {
	//	if err := s.sessionStorage.UpdateLastActivity(ctx, session.Id, kit.Now()); err != nil {
	//		s.l().Mth("session-lastactivity").E(err).Err()
	//	}
	//}()

	return session, nil
}

func (s *sessionImpl) AuthorizeSession(ctx context.Context, rq *domain.AuthorizationRequest) error {
	l := s.l().C(ctx).Mth("authorize").Dbg()

	// get token by sid
	found, session, err := s.sessionStorage.Get(ctx, rq.SessionId)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSessionNotFound(ctx)
	}

	// check session is logged out
	if session.LogoutAt != nil {
		return errors.ErrSessionLoggedOut(ctx)
	}

	// check permissions
	if len(session.Details.Roles) > 0 {
		for _, r := range rq.AuthorizationResources {
			// check request valid
			if r.Resource == "" || len(r.Permissions) == 0 {
				return errors.ErrSessionAuthorizationInvalidRequest(ctx)
			}
			// check permissions
			err = s.securityService.CheckPermissions(ctx, r.Resource, session.Details.Roles, r.Permissions)
			if err != nil {
				return err
			}
			l.DbgF("%s resource granted", r.Resource)
		}
	} else {
		return errors.ErrSessionNoRolesGranted(ctx)
	}

	return nil
}

func (s *sessionImpl) Get(ctx context.Context, sid string) (bool, *domain.Session, error) {
	s.l().C(ctx).Mth("get").F(log.FF{"sid": sid}).Dbg()
	return s.sessionStorage.Get(ctx, sid)
}

func (s *sessionImpl) GetByUser(ctx context.Context, rq *domain.GetByUserRequest) ([]*domain.Session, error) {
	s.l().C(ctx).Mth("get-by-user").Dbg().TrcObj("%v", rq)

	if rq.UserId != "" {
		return s.sessionStorage.GetByUser(ctx, rq.UserId)
	} else if rq.Username != "" {

		found, usr, err := s.userService.GetByUsername(ctx, rq.Username)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.ErrSessionNoUserFound(ctx, rq.Username)
		}
		return s.sessionStorage.GetByUser(ctx, usr.Id)

	} else {
		return nil, errors.ErrSessionGetByUsernameInvalidRequest(ctx)
	}
}

func (s *sessionImpl) RefreshToken(ctx context.Context, refreshToken string) (*domain.SessionToken, error) {
	l := s.l().C(ctx).Mth("refresh-token").Dbg()

	// verify JWT token
	_, claims, err := s.verifyJwtToken(ctx, refreshToken, s.authCfg.RefreshToken.Secret)
	if err != nil {
		return nil, err
	}

	// extract SID from claims
	sid := claims["sid"].(string)

	l.F(log.FF{"sid": sid})

	// get session
	found, session, err := s.sessionStorage.Get(ctx, sid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrSessionNotFound(ctx)
	}

	// check session is logged out
	if session.LogoutAt != nil {
		return nil, errors.ErrSessionLoggedOut(ctx)
	}

	// issue a new access token
	token, err := s.createJwtToken(ctx, session)
	if err != nil {
		return nil, err
	}

	l.Dbg("ok")

	return token, nil
}
