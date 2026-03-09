package commands

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"context"
	stderrors "errors"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/shell"
)

// Exec execute the supplied command after seeding the environment
func Exec(execFlags *flags.LoginExecFlags, cmdline []string) error {

	if len(cmdline) < 1 {
		return fmt.Errorf("Command to execute required")
	}

	account, err := buildIdpAccount(execFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if saml2aws exec is run on a new
	// system prior to creating $HOME/.aws
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required to create them")
		return nil
	}

	awsCreds, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	if time.Until(awsCreds.Expires) < 0 {
		return errors.New("error aws credentials have expired")
	}

	ok, err := checkToken(account.Profile)
	if err != nil {
		return errors.Wrap(err, "error validating token")
	}

	if !ok {
		err = Login(execFlags)
	}
	if err != nil {
		return errors.Wrap(err, "error logging in")
	}

	if execFlags.ExecProfile != "" {
		// Assume the desired role before generating env vars
		awsCreds, err = assumeRoleWithProfile(execFlags.ExecProfile, execFlags.CommonFlags.SessionDuration)
		if err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("error acquiring credentials for profile: %s", execFlags.ExecProfile))
		}
	}

	return shell.ExecShellCmd(cmdline, shell.BuildEnvVars(awsCreds, account, execFlags))
}

// assumeRoleWithProfile uses an AWS profile (via ~/.aws/config) and performs (multiple levels of) role assumption
// This is extremely useful in the case of a central "authentication account" which then requires secondary, and
// often tertiary, role assumptions to acquire credentials for the target role.
func assumeRoleWithProfile(targetProfile string, sessionDuration int) (*awsconfig.AWSCredentials, error) {
	ctx := context.Background()
	duration, _ := time.ParseDuration(strconv.Itoa(sessionDuration) + "s")

	// Load config forcing usage of the aws config file with the target profile.
	// WithAssumeRoleCredentialOptions sets the session duration for chained role assumptions.
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(targetProfile),
		config.WithAssumeRoleCredentialOptions(func(opts *stscreds.AssumeRoleOptions) {
			opts.Duration = duration
		}),
	)
	if err != nil {
		return nil, err
	}

	// Use an STS client to perform the multiple role assumptions
	stsClient := sts.NewFromConfig(awsCfg)
	_, err = stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:    creds.AccessKeyID,
		AWSSecretKey:    creds.SecretAccessKey,
		AWSSessionToken: creds.SessionToken,
		Expires:         creds.Expires,
	}, nil
}

func checkToken(profile string) (bool, error) {
	ctx := context.Background()

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return false, err
	}

	svc := sts.NewFromConfig(awsCfg)

	_, err = svc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		var apiErr smithy.APIError
		if stderrors.As(err, &apiErr) {
			// Expired token or no credential providers -> needs re-login
			if apiErr.ErrorCode() == "ExpiredTokenException" || apiErr.ErrorCode() == "ExpiredToken" {
				return false, nil
			}
			return false, err
		}
		// Non-API errors (e.g. credential provider chain found no credentials) -> needs re-login
		return false, nil
	}

	return true, nil
}
