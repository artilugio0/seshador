package seshador

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	pkAttr        = "pk" // Partition key attribute
	challengeHash = "ChallengeHash"
	encSecret     = "EncryptedSecret"
	receiverPub   = "ReceiverPubKey"
	expiration    = "Expiration"
)

type KVSDynamoDB struct {
	client    *dynamodb.Client
	tableName string
}

func NewKVSDynamoDB(client *dynamodb.Client, tableName string) *KVSDynamoDB {
	return &KVSDynamoDB{
		client:    client,
		tableName: tableName,
	}
}

// Put stores the entry with TTL set to Expiration.Unix()
func (d *KVSDynamoDB) Put(key []byte, value SecretEntry) error {
	pk := base64.URLEncoding.EncodeToString(key)

	item := map[string]interface{}{
		pkAttr:        pk,
		challengeHash: value.ChallengeHash,
		encSecret:     value.EncryptedSecret,
		receiverPub:   value.ReceiverPubKey,
		expiration:    value.Expiration.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal item: %w", err)
	}

	_, err = d.client.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName:           aws.String(d.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": pkAttr,
		},
	})
	if err != nil {
		var condFail *types.ConditionalCheckFailedException
		if errors.As(err, &condFail) {
			return errors.New("secret id already in use")
		}
		return fmt.Errorf("PutItem failed: %w", err)
	}

	return nil
}

// Get retrieves the entry (returns nil if not found or expired)
func (d *KVSDynamoDB) Get(key []byte) (*SecretEntry, error) {
	pk := base64.URLEncoding.EncodeToString(key)

	out, err := d.client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			pkAttr: &types.AttributeValueMemberS{Value: pk},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("GetItem failed: %w", err)
	}

	if out.Item == nil {
		return nil, nil // Not found
	}

	var entry SecretEntry
	if err := attributevalue.UnmarshalMap(out.Item, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
	}

	return &entry, nil
}

// Delete removes the item
func (d *KVSDynamoDB) Delete(key []byte) error {
	pk := base64.URLEncoding.EncodeToString(key)

	_, err := d.client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			pkAttr: &types.AttributeValueMemberS{Value: pk},
		},
	})
	if err != nil {
		return fmt.Errorf("DeleteItem failed: %w", err)
	}
	return nil
}
