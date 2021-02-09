package storage

import (
	"github.com/aws/aws-sdk-go/aws"
    "errors"
    "strings"
    URL "net/url"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
)

type s3storage struct {
    session *session.Session
}

func NewS3Backend() *s3storage {
    return &s3storage{
        session: session.Must(session.NewSessionWithOptions(session.Options{
            SharedConfigState: session.SharedConfigEnable,
        }))}
}

func (*s3storage) Filesizes(originalURL string) (uint64, uint64, error) {
    url, err := URL.Parse(originalURL)
	if err != nil {
		return 0, 0, err
	}

	path := strings.SplitN(url.Path, "/", 3)
	bucket := path[1]
    keyOriginal := path[2]
    keyLow := strings.Replace(keyOriginal, "_original", "_low", -1)

    sess := session.Must(session.NewSessionWithOptions(session.Options{
        SharedConfigState: session.SharedConfigEnable,
    }))
    svc := s3.New(sess)

    originalResult, err := svc.HeadObject(&s3.HeadObjectInput{
        Bucket: &bucket,
        Key: &keyOriginal,
    })
    if err != nil {
        return 0, 0, err
    }
    originalLength := *originalResult.ContentLength
    if originalLength < 0 {
        return 0, 0, errors.New("content length < 0 for original asset")
    }

    lowResult, err := svc.HeadObject(&s3.HeadObjectInput{
        Bucket: &bucket,
        Key: &keyLow,
    })
    if err != nil {
        return 0, 0, err
    }
    lowLength := *lowResult.ContentLength
    if lowLength < 0 {
        return 0, 0, errors.New("content length < 0 for low asset")
    }

    return uint64(originalLength), uint64(lowLength), nil
}

func (*s3storage) Delete(remotepaths []string) error {
    s3objects := map[string]*[]*s3.ObjectIdentifier{}

    for _, remotepath := range remotepaths {
        url, err := URL.Parse(remotepath)
        if err != nil {
            return err
        }
        path := strings.SplitN(url.Path, "/", 3)
	    bucket := path[1]
        key := path[2]

        _, ok := s3objects[bucket]
		if !ok {
			s3objects[bucket] = &[]*s3.ObjectIdentifier{}
        }
        *s3objects[bucket] = append(*s3objects[bucket], &s3.ObjectIdentifier {
            Key: &key,
        })
    }

    sess := session.Must(session.NewSessionWithOptions(session.Options{
        SharedConfigState: session.SharedConfigEnable,
    }))
    svc := s3.New(sess)

    for bucket, objects := range s3objects {
        input := &s3.DeleteObjectsInput {
            Bucket: &bucket,
            Delete: &s3.Delete{
                Objects: *objects,
                Quiet: aws.Bool(true),
            },
        }
        _, err := svc.DeleteObjects(input)
        if err != nil {
            return err
        }
    }

    return nil
}
