package go_simple_oauth2_middleware

import "github.com/markbates/goth"

type DefaultUserDetailsService struct {
	providerMap map[string][]*UserDetails
}

func NewDefaultUserDetailsService() *DefaultUserDetailsService {
	return &DefaultUserDetailsService{
		providerMap: make(map[string][]*UserDetails, 0),
	}
}

func (service *DefaultUserDetailsService) AddUserDetails(providerName string, userDetails *UserDetails) {
	userDetailsList, ok := service.providerMap[providerName]
	if !ok {
		userDetailsList = make([]*UserDetails, 0)
		service.providerMap[providerName] = userDetailsList
	}
	service.providerMap[providerName] = append(userDetailsList, userDetails)
}

func (service *DefaultUserDetailsService) GetUserDetails(user *goth.User) (*UserDetails, bool, error) {
	userDetailsList, ok := service.providerMap[user.Provider]
	if !ok {
		return nil, false, nil
	}

	for _, userDetails := range userDetailsList {
		specifiedValueCount := 0
		mismatchCount := 0
		if userDetails.UserID != "" {
			specifiedValueCount++
			if userDetails.UserID != user.UserID {
				mismatchCount++
			}
		}
		if userDetails.NickName != "" {
			specifiedValueCount++
			if userDetails.NickName != user.NickName {
				mismatchCount++
			}
		}
		if userDetails.Email != "" {
			specifiedValueCount++
			if userDetails.Email != user.Email {
				mismatchCount++
			}
		}
		if (specifiedValueCount > 0) && (mismatchCount == 0) {
			return userDetails, true, nil
		}
	}

	return nil, false, nil
}
