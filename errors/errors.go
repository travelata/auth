package errors

import (
	"context"
	authPb "github.com/travelata/auth/proto"
	"github.com/travelata/kit/er"
	"net/http"
)

var (
	ErrUserTypeIsNotCorrect = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserTypeIsNotCorrect, "user type is not correct").C(ctx).Err()
	}
	ErrUserEmailIsNotValid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserEmailIsNotValid, "user email is not valid").C(ctx).Err()
	}
	ErrUserNoEmail = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserNoEmail, "user must have email").C(ctx).Err()
	}
	ErrUserPasswordGeneration = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserPasswordGeneration, "").C(ctx).Err()
	}
	ErrUserPasswordHashGenerate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserPasswordHashGenerator, "").C(ctx).Err()
	}
	ErrUsernameNotUnique = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUsernameNotUnique, "username not unique").C(ctx).Err()
	}
	ErrUserIdEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserIdEmpty, "user id empty").C(ctx).Err()
	}
	ErrUserNotFound = func(ctx context.Context, id string) error {
		return er.WithBuilder(authPb.ErrCodeUserNotFound, "user not found").C(ctx).F(er.FF{"user": id}).Err()
	}
	ErrUserStatusNotModified = func(ctx context.Context, userId string) error {
		return er.WithBuilder(authPb.ErrCodeUserStatusNotModified, "user status not correct").C(ctx).F(er.FF{"userId": userId}).Err()
	}
	ErrUserNoGroup = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserNoGroups, "user has not groups").C(ctx).Err()
	}
	ErrUserInvalidRole = func(ctx context.Context, userId, role string) error {
		return er.WithBuilder(authPb.ErrCodeUserInvalidRole, "invalid role").C(ctx).Err()
	}
	ErrSecurityGroupCodeEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupCodeEmpty, "group code empty").C(ctx).Err()
	}
	ErrSecurityGroupNameEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupNameEmpty, "group name empty").C(ctx).Err()
	}
	ErrSecurityGroupUserTypeInvalid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupUserTypeInvalid, "user type invalid").C(ctx).Err()
	}
	ErrSecurityGroupWithCodeExists = func(ctx context.Context, g string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupWithCodeExists, "group code already exists").F(er.FF{"grp": g}).C(ctx).Err()
	}
	ErrSecurityGroupNotFound = func(ctx context.Context, g string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupNotFound, "group not found").F(er.FF{"grp": g}).C(ctx).Err()
	}
	ErrSecurityGroupModifyInternal = func(ctx context.Context, g string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupModifyInternal, "internal group cannot be modified").F(er.FF{"grp": g}).C(ctx).Err()
	}
	ErrSecurityGroupDeleteUsersExist = func(ctx context.Context, g string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupDeleteUsersExist, "group cannot be delete, users found").F(er.FF{"grp": g}).C(ctx).Err()
	}
	ErrSecurityRoleCodeEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleCodeEmpty, "role code empty").C(ctx).Err()
	}
	ErrSecurityRoleNameEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleNameEmpty, "role name empty").C(ctx).Err()
	}
	ErrSecurityRoleWithCodeExists = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleWithCodeExists, "role code already exists").F(er.FF{"role": r}).C(ctx).Err()
	}
	ErrSecurityRoleNotFound = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleNotFound, "role not found").F(er.FF{"role": r}).C(ctx).Err()
	}
	ErrSecurityResourceNotFound = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityResourceNotFound, "resource not found").F(er.FF{"resource": r}).C(ctx).Err()
	}
	ErrSecurityResourceModifyInternal = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityResourceModifyInternal, "internal resource cannot be modified").F(er.FF{"resource": r}).C(ctx).Err()
	}
	ErrSecurityRoleDeleteGroupsExist = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleDeleteGroupsExist, "role cannot be delete, groups found").F(er.FF{"role": r}).C(ctx).Err()
	}
	ErrSecurityRoleDeleteUsersExist = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleDeleteUsersExist, "role cannot be delete, users found").F(er.FF{"role": r}).C(ctx).Err()
	}
	ErrSecurityRoleModifyInternal = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleModifyInternal, "internal role cannot be modified").F(er.FF{"role": r}).C(ctx).Err()
	}
	ErrSecurityResourceDeletePermissionsExist = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityResourceDeletePermissionsExist, "related permissions exist").F(er.FF{"resource": r}).C(ctx).Err()
	}
	ErrSecurityGroupRevokeRoleNotGranted = func(ctx context.Context, g string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityGroupRevokeRoleNotGranted, "internal role cannot be delete").F(er.FF{"grp": g}).C(ctx).Err()
	}
	ErrSecurityRoleGrantPermissionNotFound = func(ctx context.Context, p string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleGrantPermissionNotFound, "permission not found").F(er.FF{"prm": p}).C(ctx).Err()
	}
	ErrSecurityRoleRevokePermissionsNotGranted = func(ctx context.Context, resource, role string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityRoleRevokePermissionsNotGranted, "permission not granted").F(er.FF{"resource": resource, "role": role}).C(ctx).Err()
	}
	ErrSecurityStorageGroupCreate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupCreate, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupUpdate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupUpdate, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupDelete = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupDelete, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupGet, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupsGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupsGet, "").C(ctx).Err()
	}
	ErrSecurityStorageRoleCreate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageRoleCreate, "").C(ctx).Err()
	}
	ErrSecurityStorageRoleUpdate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageRoleUpdate, "").C(ctx).Err()
	}
	ErrSecurityStorageRoleDelete = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageRoleDelete, "").C(ctx).Err()
	}
	ErrSecurityStorageRoleGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageRoleGet, "").C(ctx).Err()
	}
	ErrSecurityStorageRolesGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageRolesGet, "").C(ctx).Err()
	}
	ErrSecurityStorageRoleCodesGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageRoleCodesGet, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupRoleCreate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupRoleCreate, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupRoleDelete = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupRoleDelete, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupRolesGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupRolesGet, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupRoleCodesGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupRoleCodesGet, "").C(ctx).Err()
	}
	ErrSecurityStorageGroupsRoleExists = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageGroupsRoleExists, "").C(ctx).Err()
	}
	ErrSecurityStorageResourceCreate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageResourceCreate, "").C(ctx).Err()
	}
	ErrSecurityStorageResourceUpdate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageResourceUpdate, "").C(ctx).Err()
	}
	ErrSecurityStorageResourceDelete = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageResourceDelete, "").C(ctx).Err()
	}
	ErrSecurityStorageResourceGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageResourceGet, "").C(ctx).Err()
	}
	ErrSecurityStorageResourcesGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageResourcesGet, "").C(ctx).Err()
	}
	ErrSecurityStoragePermissionExists = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStoragePermissionExists, "").C(ctx).Err()
	}
	ErrSecurityStoragePermissionUpsert = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStoragePermissionUpsert, "").C(ctx).Err()
	}
	ErrSecurityStoragePermissionDelete = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStoragePermissionDelete, "").C(ctx).Err()
	}
	ErrSecurityStoragePermissionGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStoragePermissionGet, "").C(ctx).Err()
	}
	ErrSecurityStorageSearchPermissions = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageSearchPermissions, "").C(ctx).Err()
	}
	ErrSecurityStorageSearchWcPermissions = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSecurityStorageSearchWcPermissions, "").C(ctx).Err()
	}
	ErrSecurityPermissionsCheckEmptyRequest = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityPermissionsCheckEmptyRequest, "permissions request is empty").F(er.FF{"resource": r}).C(ctx).Err()
	}
	ErrSecurityPermissionsDenied = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityPermissionsDenied, "permissions denied").F(er.FF{"resource": r}).C(ctx).HttpSt(http.StatusUnauthorized).Err()
	}
	ErrSecurityPermissionsCheckInvalidRequest = func(ctx context.Context, r string, p string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityPermissionsCheckInvalidRequest, "invalid permission").F(er.FF{"resource": r, "p": p}).C(ctx).Err()
	}
	ErrSecurityResourceCodeEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityResourceCodeEmpty, "resource code empty").C(ctx).Err()
	}
	ErrSecurityResourceNameEmpty = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSecurityResourceNameEmpty, "resource name empty").C(ctx).Err()
	}
	ErrSecurityResourceWithCodeExists = func(ctx context.Context, r string) error {
		return er.WithBuilder(authPb.ErrCodeSecurityResourceWithCodeExists, "resource code already exists").F(er.FF{"resource": r}).C(ctx).Err()
	}
	ErrUserNoGroupSpecified = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserNoGroupsSpecified, "no groups").C(ctx).Err()
	}
	ErrUserGroupNotAllowed = func(ctx context.Context, group string) error {
		return er.WithBuilder(authPb.ErrCodeUserGroupNoAllowed, "user group no allowed").C(ctx).F(er.FF{"group": group}).Err()
	}
	ErrAccessTokenCreation = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeAccessTokenCreate, "error with creating access tokens").C(ctx).Err()
	}
	ErrSessionNoRolesGranted = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionNoRolesGranted, "no roles for session").C(ctx).Err()
	}
	ErrSessionNoUserFound = func(ctx context.Context, un string) error {
		return er.WithBuilder(authPb.ErrCodeSessionNoFoundForUser, "not found session for user").C(ctx).F(er.FF{"username": un}).Err()
	}
	ErrSessionUserNotActiveStatus = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionUserNotActiveStatus, "user not in active status").C(ctx).Err()
	}
	ErrSessionAuthMethodDoesntAllowLogin = func(ctx context.Context, userId string) error {
		return er.WithBuilder(authPb.ErrCodeSessionAuthMethodDoesntAllowLogin, "method not allowed for login").C(ctx).F(er.FF{"userId": userId}).Err()
	}
	ErrSessionPasswordValidation = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeUserAuthNoCorrectPassword, "password not correct").C(ctx).Err()
	}
	ErrAuthUserLoginFail = func(ctx context.Context, un string) error {
		return er.WithBuilder(authPb.ErrCodeAuthUserLoginFail, "user login fail").C(ctx).F(er.FF{"username": un}).Err()
	}
	ErrSessionAuthCodeNotProvided = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthCodeNotProvided, "auth code not provided").C(ctx).Err()
	}
	ErrSessionAuthCodeNotFound = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthCodeNotFound, "auth code not found").C(ctx).Err()
	}
	ErrSessionAuthLoginTokenInvalid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthLoginTokenNotValid, "login token not valid").C(ctx).Err()
	}
	ErrSessionAuthCodeExpired = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthCodeLoginTokenExpired, "login token expired").C(ctx).Err()
	}
	ErrSessionAuthCodeWrong = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthCodeNotValid, "auth code not valid").C(ctx).Err()
	}
	ErrSessionLoggedOut = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionLoggedOut, "can not logout").C(ctx).Err()
	}
	ErrSessionAuthWrongSigningMethod = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthTokenSigningMethodWrong, "auth token signing method not allowed").C(ctx).Err()
	}
	ErrSessionAuthTokenExpired = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthTokenExpired, "token expired").C(ctx).Err()
	}
	ErrSessionAuthTokenInvalid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthTokenIsInvalid, "token invalid").C(ctx).Err()
	}
	ErrSessionAuthTokenClaimsInvalid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeAuthTokenClaimsInvalid, "claims invalid").C(ctx).Err()
	}
	ErrSessionTokenInvalid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionTokenInvalid, "session token invalid").C(ctx).Err()
	}
	ErrSessionNotFound = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionNotFound, "session not exist").C(ctx).Err()
	}
	ErrSessionAuthorizationInvalidRequest = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionAuthorizationRequestInvalid, "request is incorrect").C(ctx).Err()
	}
	ErrSessionGetByUsernameInvalidRequest = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionGetByUsernameIncorrectRequest, "incorrect request by username").C(ctx).Err()
	}
	ErrUserStorageSetCache = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSetUserCache, "").C(ctx).Err()
	}
	ErrUserStorageCreate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserStorageCreate, "").C(ctx).Err()
	}
	ErrUserStorageUpdate = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserStorageUpdate, "").C(ctx).Err()
	}
	ErrUserStorageGetDb = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserStorageGetDb, "").C(ctx).Err()
	}
	ErrUserStorageGetCache = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserStorageGetCache, "").C(ctx).Err()
	}
	ErrUserStorageGetByIds = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserStorageGetByIds, "").C(ctx).Err()
	}
	ErrUserSearch = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeUserStorageSearchUsers, "").C(ctx).Err()
	}
	ErrSessionStorageSessionCache = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageSetCache, "").C(ctx).Err()
	}
	ErrSessionStorageGetDbEmptySid = func(ctx context.Context) error {
		return er.WithBuilder(authPb.ErrCodeSessionStorageGetDbEmptySid, "sid is empty").C(ctx).Err()
	}
	ErrSessionStorageGetDb = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageGetDb, "").C(ctx).Err()
	}
	ErrSessionStorageGetCache = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageGetCache, "").C(ctx).Err()
	}
	ErrSessionGetByUser = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageGetByUser, "").C(ctx).Err()
	}
	ErrSessionStorageCreateSession = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageCreate, "").C(ctx).Err()
	}
	ErrSessionStorageUpdateLastActivity = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageUpdateLastActivity, "").C(ctx).Err()
	}
	ErrSessionStorageUpdateLogout = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeSessionStorageUpdateLogout, "").C(ctx).Err()
	}
	ErrAuthCodeStorageMarshal = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeAuthCodeStorageMarshall, "").C(ctx).Err()
	}
	ErrAuthCodeStorageSet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeAuthCodeStorageSet, "").C(ctx).Err()
	}
	ErrAuthCodeStorageUnMarshal = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeAuthCodeStorageUnMarshall, "").C(ctx).Err()
	}
	ErrAuthCodeStorageGet = func(cause error, ctx context.Context) error {
		return er.WrapWithBuilder(cause, authPb.ErrCodeAuthCodeStorageGet, "").C(ctx).Err()
	}
)
