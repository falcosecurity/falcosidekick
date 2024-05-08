// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/embano1/memlog"
	"github.com/google/uuid"
	"github.com/xitongsys/parquet-go-source/mem"
	"github.com/xitongsys/parquet-go/writer"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	sevUnknown = iota
	sevInformational
	sevLow
	sevMedium
	sevHigh
	sevCritical
	sevFatal
)

const schemaVersion = "0.1.0"

// Security Finding [2001] Class
// https://schema.ocsf.io/classes/security_finding
type OCSFSecurityFinding struct {
	// Attacks      []OCSFAttack     `json:"attacks,omitempty" parquet:"name=attacks, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	ActivityID   int32              `json:"activity_id" parquet:"name=activity_id, type=INT32"`
	ActivityName string             `json:"activity_name" parquet:"name=activity_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	CategoryName string             `json:"category_name" parquet:"name=category_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	CategoryUID  int32              `json:"category_uid" parquet:"name=category_uid, type=INT32"`
	ClassName    string             `json:"class_name" parquet:"name=classname, type=BYTE_ARRAY, convertedtype=UTF8"`
	ClassUID     int32              `json:"class_uid" parquet:"name=class_uid, type=INT32"`
	Finding      OCSFFIndingDetails `json:"finding" parquet:"name=finding"`
	Message      string             `json:"message" parquet:"name=message, type=BYTE_ARRAY, convertedtype=UTF8"`
	Metadata     OCSFMetadata       `json:"metadata" parquet:"name=metadata"`
	Observables  []OCSFObservable   `json:"observables" parquet:"name=observables, repetitiontype=REPEATED"`
	RawData      string             `json:"raw_data" parquet:"name=raw_data, type=BYTE_ARRAY, convertedtype=UTF8"`
	Severity     string             `json:"severity" parquet:"name=severity, type=BYTE_ARRAY, convertedtype=UTF8"`
	SeverityID   int32              `json:"severity_id" parquet:"name=severity_id, type=INT32"`
	State        string             `json:"state" parquet:"name=state, type=BYTE_ARRAY, convertedtype=UTF8"`
	StateID      int32              `json:"state_id" parquet:"name=state_id, type=INT32"`
	Status       string             `json:"status" parquet:"name=status, type=BYTE_ARRAY, convertedtype=UTF8"`
	Timestamp    int64              `json:"time" parquet:"name=time, type=INT64"`
	TypeName     string             `json:"type_name" parquet:"name=type_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	TypeUID      int32              `json:"type_uid" parquet:"name=type_uid, type=INT32"`
}

// // https://schema.ocsf.io/objects/attack
// type OCSFAttack struct {
// 	Tactics       []string `json:"tactics" parquet:"name=tactics, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
// 	TechniqueUID  int32    `json:"technique_uid" parquet:"name=technique_uid, type=INT32"`
// 	TechniqueName string   `json:"technique_name" parquet:"name=technique_name, type=BYTE_ARRAY, convertedtype=UTF8"`
// }

// func (o OCSFAttack) String() string {
// 	return fmt.Sprintf("{tactics:[%s], technique_uid:%v, technique:%s}", strings.Join(o.Tactics, ","), o.TechniqueUID, o.TechniqueName)
// }

// https://schema.ocsf.io/objects/finding
type OCSFFIndingDetails struct {
	CreatedTime int64    `json:"created_time" parquet:"name=created_time, type=INT64"`
	Desc        string   `json:"desc" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	Title       string   `json:"title" parquet:"name=title, type=BYTE_ARRAY, convertedtype=UTF8"`
	Types       []string `json:"types" parquet:"name=types, type=BYTE_ARRAY, convertedtype=UTF8, repetitiontype=REPEATED"`
	UID         string   `json:"uid" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

// https://schema.ocsf.io/objects/observable
type OCSFObservable struct {
	Name   string `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Type   string `json:"type" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	TypeID int32  `json:"type_id" parquet:"name=type_id, type=INT32"`
	Value  string `json:"value" parquet:"name=value, type=BYTE_ARRAY, convertedtype=UTF8"`
}

// https://schema.ocsf.io/objects/metadata
type OCSFMetadata struct {
	Version string      `json:"version" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
	Product OCSFProduct `json:"product" parquet:"name=product"`
	Labels  []string    `json:"labels" parquet:"name=labels, type=BYTE_ARRAY, convertedtype=UTF8, repetitiontype=REPEATED"`
}

// https://schema.ocsf.io/objects/product
type OCSFProduct struct {
	VendorName string `json:"vendor_name" parquet:"name=vendor_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Name       string `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
}

func NewOCSFSecurityFinding(falcopayload types.FalcoPayload) OCSFSecurityFinding {
	ocsfsf := OCSFSecurityFinding{
		ActivityID:   1,
		ActivityName: "Generate",
		CategoryUID:  2,
		CategoryName: "Findings",
		ClassName:    "Security Finding",
		ClassUID:     2001,
		TypeUID:      200101,
		TypeName:     "Security Finding: Generate",
		// Attacks: getMitreAttacke(falcopayload.Tags),
		Metadata: OCSFMetadata{
			Labels: falcopayload.Tags,
			Product: OCSFProduct{
				Name:       "Falco",
				VendorName: "Falcosecurity",
			},
			Version: schemaVersion,
		},
		RawData: falcopayload.String(),
		State:   "New",
		StateID: 1,
		Finding: OCSFFIndingDetails{
			CreatedTime: falcopayload.Time.UnixMilli(),
			Desc:        falcopayload.Output,
			Title:       falcopayload.Rule,
			Types:       []string{falcopayload.Source},
			UID:         falcopayload.UUID,
		},
		Message:     falcopayload.Rule,
		Observables: getObservables(falcopayload.Hostname, falcopayload.OutputFields),
		Timestamp:   falcopayload.Time.UnixMilli(),
		Status:      falcopayload.Priority.String(),
	}

	ocsfsf.SeverityID, ocsfsf.Severity = getAWSSecurityLakeSeverity(falcopayload.Priority)
	return ocsfsf
}

func getObservables(hostname string, outputFields map[string]interface{}) []OCSFObservable {
	ocsfobs := []OCSFObservable{}

	if hostname != "" {
		ocsfobs = append(ocsfobs, OCSFObservable{
			Name:   "hostname",
			Type:   "Other",
			TypeID: 0,
			Value:  hostname,
		})
	}

	for i, j := range outputFields {
		switch j.(type) {
		case string, int, int16, int32, float32, float64:
			ocsfobs = append(ocsfobs, OCSFObservable{
				Name:   i,
				Type:   "Other",
				TypeID: 0,
				Value:  fmt.Sprintf("%v", j),
			})
		default:
			continue
		}
	}
	return ocsfobs
}

func getAWSSecurityLakeSeverity(priority types.PriorityType) (int32, string) {
	switch priority {
	case types.Debug, types.Informational:
		return sevInformational, "Informational"
	case types.Notice:
		return sevLow, "Low"
	case types.Warning:
		return sevMedium, "Medium"
	case types.Error:
		return sevHigh, "High"
	case types.Critical:
		return sevCritical, "Critical"
	case types.Alert, types.Emergency:
		return sevFatal, "Fatal"
	default:
		return sevUnknown, "Uknown"
	}
}

// Todo if mitre tags are becoming more precise
// func getMitreAttack(tags []string) []OCSFAttack {
// 	ocsfa := []OCSFAttack{}
// 	for _, i := range tags {
// 		if ok := strings.HasPrefix(strings.ToLower(i), "mitre_"); !ok {
// 			continue
// 		}
// 		// todo
// 	}
// 	return ocsfa
// }

func (c *Client) EnqueueSecurityLake(falcopayload types.FalcoPayload) {
	offset, err := c.Config.AWS.SecurityLake.Memlog.Write(c.Config.AWS.SecurityLake.Ctx, []byte(falcopayload.String()))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:awssecuritylake.", "status:error"})
		c.Stats.AWSSecurityLake.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awssecuritylake.", "status": Error}).Inc()
		log.Printf("[ERROR] : %v SecurityLake - %v\n", c.OutputType, err)
		return
	}
	log.Printf("[INFO]  : %v SecurityLake - Event queued (%v)\n", c.OutputType, falcopayload.UUID)
	*c.Config.AWS.SecurityLake.WriteOffset = offset
}

func (c *Client) StartSecurityLakeWorker() {
	for {
		if err := c.processNextBatch(); errors.Is(err, memlog.ErrOutOfRange) {
			// don't sleep if we're too slow reading
			continue
		}

		time.Sleep(time.Duration(c.Config.AWS.SecurityLake.Interval) * time.Minute)
	}
}

func (c *Client) processNextBatch() error {
	awslake := c.Config.AWS.SecurityLake // assumes no concurrent r/w
	ctx := awslake.Ctx
	ml := awslake.Memlog

	batch := make([]memlog.Record, awslake.BatchSize)
	count, err := ml.ReadBatch(ctx, *awslake.ReadOffset+1, batch)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			go c.CountMetric(Outputs, 1, []string{"output:awssecuritylake.", "status:error"})
			c.Stats.AWSSecurityLake.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "awssecuritylake.", "status": Error}).Inc()
			log.Printf("[ERROR] : %v SecurityLake - %v\n", c.OutputType, err)
			// ctx currently not handled in main
			// https://github.com/falcosecurity/falcosidekick/pull/390#discussion_r1081690326
			return err
		}

		if errors.Is(err, memlog.ErrOutOfRange) {
			earliest, _ := ml.Range(ctx)

			go c.CountMetric(Outputs, 1, []string{"output:awssecuritylake.", "status:error"})
			c.Stats.AWSSecurityLake.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "awssecuritylake.", "status": Error}).Inc()

			earliest = earliest - 1 // to ensure next batch includes earliest as we read from ReadOffset+1
			msg := fmt.Errorf("slow batch reader: resetting read offset from %d to %d: %v",
				*awslake.ReadOffset,
				earliest,
				err,
			)
			log.Printf("[ERROR] : %v SecurityLake - %v\n", c.OutputType, msg)
			awslake.ReadOffset = &earliest
			return err
		}

		// catch all other errors besides ErrFutureOffset which could contain a partial batch
		if !errors.Is(err, memlog.ErrFutureOffset) {
			go c.CountMetric(Outputs, 1, []string{"output:awssecuritylake.", "status:error"})
			c.Stats.AWSSecurityLake.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "awssecuritylake.", "status": Error}).Inc()
			log.Printf("[ERROR] : %v SecurityLake - %v\n", c.OutputType, err)
			return err
		}
	}

	if count > 0 {
		uid := uuid.New().String()

		if err := c.writeParquet(uid, batch[:count]); err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:awssecuritylake.", "status:error"})
			c.Stats.AWSSecurityLake.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "awssecuritylake.", "status": Error}).Inc()
			// we don't update ReadOffset to retry and not skip records
			return err
		}

		go c.CountMetric(Outputs, 1, []string{"output:awssecuritylake.", "status:ok"})
		c.Stats.AWSSecurityLake.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awssecuritylake.", "status": "ok"}).Inc()

		// update offset
		*awslake.ReadOffset = batch[count-1].Metadata.Offset
	}

	return nil
}

func (c *Client) writeParquet(uid string, records []memlog.Record) error {
	fw, err := mem.NewMemFileWriter(uid+".parquet", func(name string, r io.Reader) error {
		t := time.Now()
		key := fmt.Sprintf("/%s/region=%s/accountId=%s/eventDay=%s/%s.parquet", c.Config.AWS.SecurityLake.Prefix, c.Config.AWS.SecurityLake.Region, c.Config.AWS.SecurityLake.AccountID, t.Format("20060102"), uid)
		ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFn()
		resp, err := s3.New(c.AWSSession).PutObjectWithContext(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(c.Config.AWS.SecurityLake.Bucket),
			Key:         aws.String(key),
			Body:        aws.ReadSeekCloser(r),
			ContentType: aws.String("Apache Parquet"),
			ACL:         aws.String(s3.ObjectCannedACLBucketOwnerFullControl),
		})
		if err != nil {
			log.Printf("[ERROR] : %v SecurityLake - Upload parquet file %s.parquet Failed: %v\n", c.OutputType, uid, err)
			return err
		}
		if resp.SSECustomerAlgorithm != nil {
			log.Printf("[INFO]  : %v SecurityLake - Upload parquet file %s.parquet OK (%v) (%v events) \n", c.OutputType, uid, *resp.SSECustomerKeyMD5, len(records))
		} else {
			log.Printf("[INFO]  : %v SecurityLake - Upload parquet file %s.parquet OK (%v events)\n", c.OutputType, uid, len(records))
		}
		return nil
	})
	if err != nil {
		log.Printf("[ERROR] : %v SecurityLake - Can't create the parquet file %s.parquet: %v\n", c.OutputType, uid, err)
		return err
	}
	pw, err := writer.NewParquetWriter(fw, new(OCSFSecurityFinding), 10)
	if err != nil {
		log.Printf("[ERROR] : %v SecurityLake - Can't create the parquet writer: %v\n", c.OutputType, err)
		return err
	}
	for _, i := range records {
		var f types.FalcoPayload
		if err := json.Unmarshal(i.Data, &f); err != nil {
			log.Printf("[ERROR] : %v SecurityLake - Unmarshalling error: %v\n", c.OutputType, err)
			continue
		}
		o := NewOCSFSecurityFinding(f)
		if err = pw.Write(o); err != nil {
			log.Printf("[ERROR] : %v SecurityLake - Parquet writer error: %v\n", c.OutputType, err)
			continue
		}
	}
	if err = pw.WriteStop(); err != nil {
		log.Printf("[ERROR] : %v SecurityLake - Can't stop the parquet writer: %v\n", c.OutputType, err)
	}
	if err = fw.Close(); err != nil {
		log.Printf("[ERROR] : %v SecurityLake - Can't close the parquet file %s.parquet: %v\n", c.OutputType, uid, err)
		return err
	}
	return nil
}
