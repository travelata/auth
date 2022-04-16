package users

import (
	"context"
	"github.com/travelata/auth/config"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	authPb "github.com/travelata/auth/proto"
	"github.com/travelata/kit"
	"github.com/travelata/kit/common"
	"github.com/travelata/kit/log"
	"golang.org/x/crypto/bcrypt"
)

// userTypeCfg defines internal configuration of different user types
type userTypeCfg struct {
	// authType - type of authentication
	authType string
	// allowLogin - if user of the given type can login
	allowLogin bool
}

var (
	userTypeCfgMap = map[string]userTypeCfg{
		authPb.USER_TYPE_ADMIN: {
			authType:   domain.AuthTypePassword,
			allowLogin: true,
		},
		authPb.USER_TYPE_MODERATOR: {
			authType:   domain.AuthTypeCode,
			allowLogin: true,
		},
		authPb.USER_TYPE_BLOCKED: {
			authType:   domain.AuthTypeNone,
			allowLogin: false,
		},
		authPb.USER_TYPE_READER: {
			authType:   domain.AuthTypeCode,
			allowLogin: true,
		},
		authPb.USER_TYPE_REGULAR: {
			authType:   domain.AuthTypeCode,
			allowLogin: true,
		},
		authPb.USER_TYPE_SUPPORT: {
			authType:   domain.AuthTypePassword,
			allowLogin: true,
		},
		authPb.USER_TYPE_TECH: {
			authType:   domain.AuthTypePassword,
			allowLogin: true,
		},
	}
)

type userSvcImpl struct {
	storage           domain.UserStorage
	passwordGenerator domain.PasswordGenerator
	securityService   domain.SecurityService
}

func NewUserService(passwordGenerator domain.PasswordGenerator, storage domain.UserStorage, securityService domain.SecurityService) domain.UserService {
	return &userSvcImpl{
		passwordGenerator: passwordGenerator,
		storage:           storage,
		securityService:   securityService,
	}
}

func (u *userSvcImpl) l() log.CLogger {
	return logger.L().Cmp("user-service")
}

func (u *userSvcImpl) addGroups(ctx context.Context, usr *domain.User, addingGroups []string) (*domain.User, error) {

	l := u.l().C(ctx).Mth("add-groups").Dbg()

	// get groups associated with user type
	groups, err := u.securityService.GetGroupsByUserType(ctx, usr.Type)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, errors.ErrUserNoGroupSpecified(ctx)
	}
	var defaultGroups []string
	for _, g := range groups {
		if g.Default {
			defaultGroups = append(defaultGroups, g.Code)
		}
	}

	// check groups
	if len(addingGroups) == 0 && len(usr.Details.Groups) == 0 {
		// if request doesn't contain any groups, set default
		usr.Details.Groups = defaultGroups
	} else {
		modifiedGroups := usr.Details.Groups
		for _, g := range addingGroups {
			allowed := false
			for _, cfgG := range groups {
				if g == cfgG.Code {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, errors.ErrUserGroupNotAllowed(ctx, g)
			}
			// check existent groups
			duplicate := false
			for _, usrG := range usr.Details.Groups {
				if usrG == g {
					l.WarnF("group %s duplicated, skipped", g)
					duplicate = true
					break
				}
			}
			if !duplicate {
				modifiedGroups = append(modifiedGroups, g)
			}
		}
		usr.Details.Groups = modifiedGroups
	}
	if len(usr.Details.Groups) == 0 {
		return nil, errors.ErrUserNoGroup(ctx)
	}

	return usr, nil
}

func (u *userSvcImpl) Init(c *config.Config) {
	u.passwordGenerator.Init(c.Auth.Password)
}

func (u *userSvcImpl) Create(ctx context.Context, request *domain.CreateUserRequest) (*domain.User, error) {
	l := u.l().C(ctx).Mth("create").Dbg()

	cfg, ok := userTypeCfgMap[request.Type]
	if !ok {
		return nil, errors.ErrUserTypeIsNotCorrect(ctx)
	}

	//check email
	if request.Email == "" {
		return nil, errors.ErrUserNoEmail(ctx)
	}
	if request.Email != "" && !kit.IsEmailValid(request.Email) {
		return nil, errors.ErrUserEmailIsNotValid(ctx)
	}

	// check and hash password
	var (
		passwordHash, password string
		err                    error
	)
	if cfg.authType == domain.AuthTypePassword {
		if request.Password == "" {
			if password, err = u.passwordGenerator.Generate(ctx); err != nil {
				return nil, errors.ErrUserPasswordGeneration(err, ctx)
			}
		} else {
			password = request.Password
		}

		if bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err == nil {
			passwordHash = string(bytes)
		} else {
			return nil, errors.ErrUserPasswordHashGenerate(err, ctx)
		}
	}

	createdAt := kit.Now()
	user := &domain.User{
		Id:       kit.NewId(),
		Username: request.Username,
		Type:     request.Type,
		AuthType: cfg.authType,
		Status:   authPb.USER_STATUS_DRAFT,
		Password: passwordHash,
		Details: &domain.UserDetails{
			FirstName: request.FirstName,
			LastName:  request.LastName,
			Email:     request.Email,
			Avatar:    request.Avatar,
			Introduce: request.Introduce,
		},
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}
	l.F(log.FF{"id": user.Id})

	//check username
	if found, _, _ := u.storage.GetByUsername(ctx, user.Username); found {
		return nil, errors.ErrUsernameNotUnique(ctx)
	}

	err = u.storage.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	l.Dbg("created")

	return user, nil
}

func (u *userSvcImpl) GetByUsername(ctx context.Context, un string) (bool, *domain.User, error) {
	u.l().C(ctx).Mth("get-by-username").F(log.FF{"username": un}).Dbg()

	return u.storage.GetByUsername(ctx, un)
}

func (u *userSvcImpl) Get(ctx context.Context, id string) (bool, *domain.User, error) {
	u.l().C(ctx).Mth("get").F(log.FF{"id": id}).Dbg()

	return u.storage.Get(ctx, id)
}

func (u *userSvcImpl) GetByIds(ctx context.Context, ids []string) ([]*domain.User, error) {
	u.l().C(ctx).Mth("get-by-ids").F(log.FF{"id": ids}).Dbg()

	return u.storage.GetByIds(ctx, ids)
}

func (u *userSvcImpl) UpdateUserDetails(ctx context.Context, userId string, details *domain.UserDetails) (*domain.User, error) {
	u.l().C(ctx).Mth("update-details").F(log.FF{"userId": userId}).Dbg()

	if userId == "" {
		return nil, errors.ErrUserIdEmpty(ctx)
	}

	//getting user
	found, store, err := u.Get(ctx, userId)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.ErrUserNotFound(ctx, userId)
	}

	if store.Status != authPb.USER_STATUS_ACTIVE && store.Status != authPb.USER_STATUS_DRAFT {
		return nil, errors.ErrUserStatusNotModified(ctx, store.Id)
	}

	store.Details.Email = details.Email
	store.Details.Avatar = details.Avatar
	store.Details.LastName = details.LastName
	store.Details.FirstName = details.FirstName
	store.Details.Bio = details.Bio
	store.UpdatedAt = kit.Now()

	err = u.storage.Update(ctx, store)
	if err != nil {
		return nil, err
	}

	return store, nil
}

func (u *userSvcImpl) SetStatus(ctx context.Context, userId string, status string) (*domain.User, error) {
	l := u.l().C(ctx).Mth("set-status").F(log.FF{"userId": userId, "status": status}).Dbg()

	if userId == "" {
		return nil, errors.ErrUserIdEmpty(ctx)
	}

	found, storage, err := u.Get(ctx, userId)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.ErrUserNotFound(ctx, userId)
	}

	if storage.Status == status {
		l.Warn("user already in status")
		return storage, nil
	}

	now := kit.Now()
	if status == authPb.USER_STATUS_DELETED {
		storage.DeletedAt = &now
	}

	storage.Status = status
	storage.UpdatedAt = now

	err = u.storage.Update(ctx, storage)
	if err != nil {
		return nil, err
	}

	return storage, nil
}

func (u *userSvcImpl) Search(ctx context.Context, cr *domain.UserSearchCriteria) (*domain.UserSearchResponse, error) {
	u.l().C(ctx).Mth("search").Dbg()

	if cr.PagingRequest == nil {
		cr.PagingRequest = &common.PagingRequest{}
	}

	if cr.Size == 0 {
		cr.Size = 100
	}

	return u.storage.Search(ctx, cr)
}

func (u *userSvcImpl) AddGroups(ctx context.Context, userId string, groups []string) (*domain.User, error) {
	u.l().C(ctx).Mth("add-groups").F(log.FF{"userId": userId}).Dbg()

	// find user
	found, user, err := u.storage.Get(ctx, userId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrUserNotFound(ctx, userId)
	}

	// add groups
	user, err = u.addGroups(ctx, user, groups)
	if err != nil {
		return nil, err
	}

	user.UpdatedAt = kit.Now()

	// update storage
	err = u.storage.Update(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *userSvcImpl) DeleteGroups(ctx context.Context, userId string, groups []string) (*domain.User, error) {
	u.l().C(ctx).Mth("delete-groups").F(log.FF{"userId": userId}).Dbg()

	// find user
	found, user, err := u.storage.Get(ctx, userId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrUserNotFound(ctx, userId)
	}

	var modifiedGroups []string
	for _, userGr := range user.Details.Groups {
		found = false
		for _, deletedGr := range groups {
			if deletedGr == userGr {
				found = true
				break
			}
		}
		if !found {
			modifiedGroups = append(modifiedGroups, userGr)
		}
	}
	user.Details.Groups = modifiedGroups

	// check if at least one group should be assigned
	if len(user.Details.Groups) == 0 {
		return nil, errors.ErrUserNoGroup(ctx)
	}
	// update storage
	err = u.storage.Update(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *userSvcImpl) GrantRoles(ctx context.Context, userId string, roles []string) (*domain.User, error) {
	u.l().C(ctx).Mth("grant-roles").F(log.FF{"userId": userId}).Dbg()

	// find user
	found, user, err := u.storage.Get(ctx, userId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrUserNotFound(ctx, userId)
	}

	// get all roles
	allRoles, err := u.securityService.GetAllRoles(ctx)
	if err != nil {
		return nil, err
	}
	var rolesMap = make(map[string]struct{})
	for _, r := range allRoles {
		rolesMap[r.Code] = struct{}{}
	}

	modifiedRoles := user.Details.Roles
	for _, r := range roles {
		if _, ok := rolesMap[r]; !ok {
			return nil, errors.ErrUserInvalidRole(ctx, userId, r)
		}
		duplicate := false
		for _, usrRole := range modifiedRoles {
			if r == usrRole {
				duplicate = true
				break
			}
		}
		if !duplicate {
			modifiedRoles = append(modifiedRoles, r)
		}
	}
	user.Details.Roles = modifiedRoles
	user.UpdatedAt = kit.Now()

	// update storage
	err = u.storage.Update(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *userSvcImpl) RevokeRoles(ctx context.Context, userId string, roles []string) (*domain.User, error) {
	u.l().C(ctx).Mth("revoke-roles").F(log.FF{"userId": userId}).Dbg()

	// find user
	found, user, err := u.storage.Get(ctx, userId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrUserNotFound(ctx, userId)
	}

	var modifiedRoles []string
	for _, userRole := range user.Details.Roles {
		found = false
		for _, revokedRole := range roles {
			if revokedRole == userRole {
				found = true
				break
			}
		}
		if !found {
			modifiedRoles = append(modifiedRoles, userRole)
		}
	}
	user.Details.Roles = modifiedRoles
	user.UpdatedAt = kit.Now()

	// update storage
	err = u.storage.Update(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *userSvcImpl) ResetPassword(ctx context.Context, userId string) error {
	//TODO implement me
	panic("implement me")
}
