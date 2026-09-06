/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/go-logr/logr"
	b2v1alpha2 "github.com/mgruszkiewicz/backblaze-operator/api/v1alpha2"
	"github.com/mgruszkiewicz/go-backblaze"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const keyFinalizer = "key.b2.issei.space/finalizer"

const (
	defaultKeySecretName        = "b2-secret"
	keySecretSpecHashAnnotation = "b2.issei.space/key-spec-hash"
	retryKeyCreationAnnotation  = "b2.issei.space/retry-creation"
	uncertainCreationMessage    = "Application key creation may have succeeded, but no credential receipt is available. Verify and delete any provider key created for this resource, then set b2.issei.space/retry-creation=true to retry."
)

// KeyReconciler reconciles a Key object
type KeyReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	Backblaze     B2Client
	EventRecorder record.EventRecorder
}

// setReadyCondition records the Ready condition on the Key and persists it.
// Failures to persist are logged only, so callers can still return the
// original reconcile error.
func (r *KeyReconciler) setReadyCondition(ctx context.Context, key *b2v1alpha2.Key, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             status,
		ObservedGeneration: key.Generation,
		Reason:             reason,
		Message:            message,
	})
	if err := r.Status().Update(ctx, key); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update Key status")
	}
}

//+kubebuilder:rbac:groups=b2.issei.space,resources=keys,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=b2.issei.space,resources=buckets,verbs=get;list;watch
//+kubebuilder:rbac:groups=b2.issei.space,resources=keys/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=b2.issei.space,resources=keys/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *KeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	key := &b2v1alpha2.Key{}

	if err := r.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: req.Namespace}, key); err != nil {
		if errors.IsNotFound(err) {
			// object not found, could have been deleted after
			// reconcile request, hence don't requeue
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(key, keyFinalizer) {
		l.Info("Adding Finalizer")
		controllerutil.AddFinalizer(key, keyFinalizer)
		return ctrl.Result{}, r.Update(ctx, key)
	}

	if !key.DeletionTimestamp.IsZero() {
		l.Info("Key is being deleted")
		return r.reconcileDelete(ctx, key, true)
	}

	return r.reconcileCreate(ctx, key)
}

func (r *KeyReconciler) reconcileCreate(ctx context.Context, key *b2v1alpha2.Key) (ctrl.Result, error) {
	// Create or update the key
	if err := r.createOrUpdateKey(ctx, key); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *KeyReconciler) createKeySecret(ctx context.Context, key *b2v1alpha2.Key, appkey *backblaze.ApplicationKeyResponse) error {
	l := log.FromContext(ctx)
	secretName := keySecretName(key)

	secretData := map[string][]byte{
		"bucketName": []byte(key.Spec.AtProvider.BucketName),
		"endpoint":   []byte(fmt.Sprintf("s3.%s.backblazeb2.com", string(os.Getenv("B2_REGION")))),
		"keyName":    []byte(appkey.KeyName),
		// AWS S3 compatible variables
		"AWS_ACCESS_KEY_ID":     []byte(appkey.ApplicationKeyId),
		"AWS_SECRET_ACCESS_KEY": []byte(appkey.ApplicationKey),
	}
	hash, err := keySpecHash(key.Spec.AtProvider)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   key.Namespace,
			Annotations: map[string]string{keySecretSpecHashAnnotation: hash},
		},
		Data: secretData,
	}
	if err := controllerutil.SetControllerReference(key, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set Secret owner: %w", err)
	}
	if err := r.Create(ctx, secret); err != nil {
		l.Error(err, "Failed to create Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		return fmt.Errorf("failed to create Secret: %w", err)
	}
	return nil
}

func (r *KeyReconciler) createOrUpdateKey(ctx context.Context, key *b2v1alpha2.Key) error {
	l := log.FromContext(ctx)
	if err := r.Get(ctx, types.NamespacedName{Name: key.Name, Namespace: key.Namespace}, key); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("unable to fetch Key: %w", err)
		}
	}

	if key.Spec.AtProvider.NamePrefix != "" && key.Spec.AtProvider.BucketName == "" && key.Spec.AtProvider.BucketId == "" {
		msg := "namePrefix requires bucketName or bucketId"
		r.setReadyCondition(ctx, key, metav1.ConditionFalse, ReasonInvalidSpec, msg)
		return fmt.Errorf("invalid Key spec: %s", msg)
	}

	if key.Status.Reconciled {
		if !reflect.DeepEqual(key.Spec.AtProvider, key.Status.AtProvider) {
			if err := r.ensureSecretOwnedForRotation(ctx, key); err != nil {
				return err
			}
			key.Status.Reconciled = false
			key.Status.ToRecreate = true
			setKeyCondition(key, metav1.ConditionFalse, ReasonKeyRotating, "Key rotation is in progress")
			return r.Status().Update(ctx, key)
		}
		return r.verifyReadySecret(ctx, key)
	}

	if key.Status.ToRecreate {
		if key.Status.KeyId != "" {
			return r.finishKeyRotation(ctx, key)
		}
		return r.recoverOrBlockUncertainCreation(ctx, key)
	}

	request, err := r.createKeyRequest(ctx, key)
	if err != nil {
		return err
	}
	if recovered, err := r.recoverFromSecret(ctx, key); err != nil || recovered {
		return err
	}

	key.Status.AtProvider = key.Spec.AtProvider
	key.Status.ToRecreate = true
	setKeyCondition(key, metav1.ConditionFalse, ReasonKeyCreating, "Application key creation is in progress")
	if err := r.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("failed to record Key creation state: %w", err)
	}

	applicationKey, err := r.Backblaze.CreateApplicationKey(request)
	if err != nil {
		safeErr := safeProviderError(err)
		l.Error(safeErr, "Unable to create application key at provider")
		if isDefinitiveProviderRejection(err) {
			key.Status.ToRecreate = false
			setKeyCondition(key, metav1.ConditionFalse, ReasonKeyCreationFailed, safeErr.Error())
			if statusErr := r.Status().Update(ctx, key); statusErr != nil {
				return fmt.Errorf("%v; failed to update Key status: %w", safeErr, statusErr)
			}
		} else {
			setKeyCondition(key, metav1.ConditionFalse, ReasonKeyCreationUncertain, uncertainCreationMessage)
			if statusErr := r.Status().Update(ctx, key); statusErr != nil {
				return fmt.Errorf("%v; failed to update Key status: %w", safeErr, statusErr)
			}
		}
		return fmt.Errorf("unable to create application key: %w", safeErr)
	}
	if applicationKey == nil || applicationKey.ApplicationKeyId == "" {
		setKeyCondition(key, metav1.ConditionFalse, ReasonKeyCreationUncertain, uncertainCreationMessage)
		if statusErr := r.Status().Update(ctx, key); statusErr != nil {
			return fmt.Errorf("provider returned incomplete application key; failed to update Key status: %w", statusErr)
		}
		return fmt.Errorf("provider returned incomplete application key; %s", uncertainCreationMessage)
	}
	if applicationKey.ApplicationKey == "" {
		return r.handleSecretPublicationFailure(ctx, key, applicationKey.ApplicationKeyId, fmt.Errorf("provider returned no application key secret"))
	}

	if err := r.createKeySecret(ctx, key, applicationKey); err != nil {
		return r.handleSecretPublicationFailure(ctx, key, applicationKey.ApplicationKeyId, err)
	}

	key.Status.Reconciled = true
	key.Status.ToRecreate = false
	key.Status.AtProvider = key.Spec.AtProvider
	key.Status.KeyId = applicationKey.ApplicationKeyId
	condition := meta.FindStatusCondition(key.Status.Conditions, ConditionTypeReady)
	if condition != nil && condition.Status == metav1.ConditionTrue && condition.Reason == ReasonReconciled && condition.ObservedGeneration == key.Generation {
		return nil
	}
	setKeyCondition(key, metav1.ConditionTrue, ReasonReconciled, "Key and credential Secret reconciled")
	if err := r.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("failed to update Key status: %w", err)
	}
	return nil
}

func (r *KeyReconciler) createKeyRequest(ctx context.Context, key *b2v1alpha2.Key) (*backblaze.CreateKeyRequest, error) {
	bucketID := key.Spec.AtProvider.BucketId
	if key.Spec.AtProvider.BucketName != "" {
		bucket, err := r.Backblaze.Bucket(key.Spec.AtProvider.BucketName)
		if err != nil {
			safeErr := safeProviderError(err)
			log.FromContext(ctx).Error(safeErr, "Failed to fetch bucket at provider")
			r.setReadyCondition(ctx, key, metav1.ConditionFalse, ReasonProviderError, safeErr.Error())
			return nil, fmt.Errorf("unable to fetch bucket at provider: %w", safeErr)
		}
		if bucket == nil {
			msg := "referenced bucket was not found at provider"
			if r.EventRecorder != nil {
				r.EventRecorder.Event(key, corev1.EventTypeWarning, ReasonBucketNotFound, msg)
			}
			r.setReadyCondition(ctx, key, metav1.ConditionFalse, ReasonBucketNotFound, msg)
			return nil, fmt.Errorf("%s", msg)
		}
		bucketID = bucket.ID
	}

	return &backblaze.CreateKeyRequest{
		KeyName:                key.Name,
		Capabilities:           key.Spec.AtProvider.Capabilities,
		ValidDurationInSeconds: key.Spec.AtProvider.ValidDurationInSeconds,
		BucketId:               bucketID,
		NamePrefix:             key.Spec.AtProvider.NamePrefix,
	}, nil
}

func (r *KeyReconciler) recoverFromSecret(ctx context.Context, key *b2v1alpha2.Key) (bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: keySecretName(key), Namespace: key.Namespace}, secret)
	if errors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get credential Secret: %w", err)
	}
	if !secretReceiptMatches(key, secret) {
		return false, r.recordSecretConflict(ctx, key)
	}

	key.Status.Reconciled = true
	key.Status.ToRecreate = false
	key.Status.AtProvider = key.Spec.AtProvider
	key.Status.KeyId = string(secret.Data["AWS_ACCESS_KEY_ID"])
	setKeyCondition(key, metav1.ConditionTrue, ReasonReconciled, "Recovered Key status from credential Secret")
	if err := r.Status().Update(ctx, key); err != nil {
		return false, fmt.Errorf("failed to recover Key status: %w", err)
	}
	return true, nil
}

func (r *KeyReconciler) recoverOrBlockUncertainCreation(ctx context.Context, key *b2v1alpha2.Key) error {
	if recovered, err := r.recoverFromSecret(ctx, key); err != nil || recovered {
		return err
	}
	if key.Annotations[retryKeyCreationAnnotation] == "true" {
		delete(key.Annotations, retryKeyCreationAnnotation)
		if err := r.Update(ctx, key); err != nil {
			return fmt.Errorf("failed to consume retry annotation: %w", err)
		}
		key.Status.ToRecreate = false
		setKeyCondition(key, metav1.ConditionFalse, ReasonKeyCreating, "Explicit retry accepted")
		if err := r.Status().Update(ctx, key); err != nil {
			return fmt.Errorf("failed to reset Key creation state: %w", err)
		}
		return nil
	}

	setKeyCondition(key, metav1.ConditionFalse, ReasonKeyCreationUncertain, uncertainCreationMessage)
	if err := r.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("failed to update uncertain Key status: %w", err)
	}
	return fmt.Errorf("application key creation outcome is uncertain; explicit recovery is required")
}

func (r *KeyReconciler) verifyReadySecret(ctx context.Context, key *b2v1alpha2.Key) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: keySecretName(key), Namespace: key.Namespace}, secret)
	if errors.IsNotFound(err) {
		key.Status.Reconciled = false
		key.Status.ToRecreate = true
		setKeyCondition(key, metav1.ConditionFalse, ReasonSecretMissing, "Credential Secret is missing; controlled key rotation is pending")
		return r.Status().Update(ctx, key)
	}
	if err != nil {
		return fmt.Errorf("failed to get credential Secret: %w", err)
	}

	owned := metav1.IsControlledBy(secret, key)
	if !owned && !legacySecretMatches(key, secret) {
		return r.recordSecretConflict(ctx, key)
	}
	hash, err := keySpecHash(key.Spec.AtProvider)
	if err != nil {
		return err
	}
	valid := bytes.Equal(secret.Data["AWS_ACCESS_KEY_ID"], []byte(key.Status.KeyId)) &&
		len(secret.Data["AWS_SECRET_ACCESS_KEY"]) > 0 &&
		bytes.Equal(secret.Data["keyName"], []byte(key.Name)) &&
		(secret.Annotations[keySecretSpecHashAnnotation] == "" || secret.Annotations[keySecretSpecHashAnnotation] == hash)
	if !valid {
		key.Status.Reconciled = false
		key.Status.ToRecreate = true
		setKeyCondition(key, metav1.ConditionFalse, ReasonSecretInvalid, "Credential Secret does not match provider state; controlled key rotation is pending")
		return r.Status().Update(ctx, key)
	}

	changed := false
	if !owned {
		if err := controllerutil.SetControllerReference(key, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to adopt legacy credential Secret: %w", err)
		}
		changed = true
	}
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	if secret.Annotations[keySecretSpecHashAnnotation] != hash {
		secret.Annotations[keySecretSpecHashAnnotation] = hash
		changed = true
	}
	if changed {
		if err := r.Update(ctx, secret); err != nil {
			return fmt.Errorf("failed to adopt credential Secret: %w", err)
		}
	}
	setKeyCondition(key, metav1.ConditionTrue, ReasonReconciled, "Key and credential Secret reconciled")
	if err := r.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("failed to update Key status: %w", err)
	}
	return nil
}

func (r *KeyReconciler) ensureSecretOwnedForRotation(ctx context.Context, key *b2v1alpha2.Key) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: keySecretName(key), Namespace: key.Namespace}, secret)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get credential Secret: %w", err)
	}
	if !metav1.IsControlledBy(secret, key) && !legacySecretMatches(key, secret) {
		return r.recordSecretConflict(ctx, key)
	}
	if !metav1.IsControlledBy(secret, key) {
		if err := controllerutil.SetControllerReference(key, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to adopt legacy credential Secret: %w", err)
		}
		if err := r.Update(ctx, secret); err != nil {
			return fmt.Errorf("failed to adopt legacy credential Secret: %w", err)
		}
	}
	return nil
}

func (r *KeyReconciler) finishKeyRotation(ctx context.Context, key *b2v1alpha2.Key) error {
	// If desired and observed specs match, this state came from a failed
	// credential publication or missing Secret. Preserve any unrelated Secret.
	preserveUnrelated := reflect.DeepEqual(key.Status.AtProvider, key.Spec.AtProvider)
	if err := r.deleteKeySecret(ctx, key, preserveUnrelated); err != nil {
		return err
	}
	if _, err := r.Backblaze.DeleteApplicationKey(key.Status.KeyId); err != nil && !isProviderNotFound(err) {
		safeErr := safeProviderError(err)
		setKeyCondition(key, metav1.ConditionFalse, ReasonKeyRotating, safeErr.Error())
		if statusErr := r.Status().Update(ctx, key); statusErr != nil {
			return fmt.Errorf("%v; failed to update Key status: %w", safeErr, statusErr)
		}
		return fmt.Errorf("failed to revoke application key during rotation: %w", safeErr)
	}

	key.Status.KeyId = ""
	key.Status.Reconciled = false
	key.Status.ToRecreate = false
	setKeyCondition(key, metav1.ConditionFalse, ReasonKeyRotating, "Previous application key revoked; replacement is pending")
	if err := r.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("failed to record application key revocation: %w", err)
	}
	return nil
}

func (r *KeyReconciler) handleSecretPublicationFailure(ctx context.Context, key *b2v1alpha2.Key, keyID string, publicationErr error) error {
	_, deleteErr := r.Backblaze.DeleteApplicationKey(keyID)
	if deleteErr != nil && !isProviderNotFound(deleteErr) {
		safeErr := safeProviderError(deleteErr)
		key.Status.KeyId = keyID
		setKeyCondition(key, metav1.ConditionFalse, ReasonSecretWriteFailed, "Credential Secret publication failed; provider key cleanup is pending")
		if statusErr := r.Status().Update(ctx, key); statusErr != nil {
			return fmt.Errorf("failed to create credential Secret; %v; failed to record provider key for cleanup: %w", safeErr, statusErr)
		}
		return fmt.Errorf("failed to create credential Secret; provider cleanup also failed: %w", safeErr)
	}

	key.Status.KeyId = ""
	key.Status.ToRecreate = false
	setKeyCondition(key, metav1.ConditionFalse, ReasonSecretWriteFailed, "Credential Secret publication failed; created provider key was revoked")
	if statusErr := r.Status().Update(ctx, key); statusErr != nil {
		return fmt.Errorf("%v; failed to reset Key status: %w", publicationErr, statusErr)
	}
	return publicationErr
}

func (r *KeyReconciler) deleteKeySecret(ctx context.Context, key *b2v1alpha2.Key, preserveUnrelated bool) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: keySecretName(key), Namespace: key.Namespace}, secret)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get credential Secret during deletion: %w", err)
	}
	if !metav1.IsControlledBy(secret, key) && !legacySecretMatches(key, secret) {
		if preserveUnrelated {
			log.FromContext(ctx).Info("Preserving credential Secret not owned by Key", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
			return nil
		}
		return r.recordSecretConflict(ctx, key)
	}
	if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete credential Secret: %w", err)
	}
	return nil
}

func (r *KeyReconciler) recordSecretConflict(ctx context.Context, key *b2v1alpha2.Key) error {
	message := "Credential Secret already exists but is not a valid receipt owned by this Key; it was not changed"
	if r.EventRecorder != nil {
		r.EventRecorder.Event(key, corev1.EventTypeWarning, ReasonSecretConflict, message)
	}
	setKeyCondition(key, metav1.ConditionFalse, ReasonSecretConflict, message)
	if err := r.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("%s; failed to update Key status: %w", message, err)
	}
	return fmt.Errorf("%s", message)
}

func keySecretName(key *b2v1alpha2.Key) string {
	if key.Spec.WriteConnectionSecretToRef.Name != "" {
		return key.Spec.WriteConnectionSecretToRef.Name
	}
	return defaultKeySecretName
}

func keySpecHash(spec b2v1alpha2.KeySpecAtProvider) (string, error) {
	serialized, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to hash Key spec: %w", err)
	}
	sum := sha256.Sum256(serialized)
	return hex.EncodeToString(sum[:]), nil
}

func secretReceiptMatches(key *b2v1alpha2.Key, secret *corev1.Secret) bool {
	hash, err := keySpecHash(key.Spec.AtProvider)
	return err == nil && metav1.IsControlledBy(secret, key) &&
		secret.Annotations[keySecretSpecHashAnnotation] == hash &&
		len(secret.Data["AWS_ACCESS_KEY_ID"]) > 0 &&
		len(secret.Data["AWS_SECRET_ACCESS_KEY"]) > 0 &&
		bytes.Equal(secret.Data["keyName"], []byte(key.Name))
}

func legacySecretMatches(key *b2v1alpha2.Key, secret *corev1.Secret) bool {
	return metav1.GetControllerOf(secret) == nil && key.Status.KeyId != "" &&
		bytes.Equal(secret.Data["AWS_ACCESS_KEY_ID"], []byte(key.Status.KeyId)) &&
		bytes.Equal(secret.Data["keyName"], []byte(key.Name)) &&
		len(secret.Data["AWS_SECRET_ACCESS_KEY"]) > 0
}

func setKeyCondition(key *b2v1alpha2.Key, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             status,
		ObservedGeneration: key.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *KeyReconciler) reconcileDelete(ctx context.Context, key *b2v1alpha2.Key, deleteSecret bool) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	l.Info("Removing Key")

	if deleteSecret {
		if err := r.deleteKeySecret(ctx, key, true); err != nil {
			return ctrl.Result{}, err
		}
	}

	if key.Status.KeyId != "" {
		if _, err := r.Backblaze.DeleteApplicationKey(key.Status.KeyId); err != nil {
			if !isProviderNotFound(err) {
				safeErr := safeProviderError(err)
				l.Error(safeErr, "Failed to delete application key")
				return ctrl.Result{}, fmt.Errorf("failed to delete application key: %w", safeErr)
			}
		}
	}

	controllerutil.RemoveFinalizer(key, keyFinalizer)
	if err := r.Update(ctx, key); err != nil {
		return ctrl.Result{}, fmt.Errorf("error removing finalizer: %w", err)
	}

	return ctrl.Result{}, nil
}

// keysForBucket maps a Bucket event to reconcile requests for all Keys that
// reference that bucket by name and are still waiting to be reconciled, so a
// Key blocked on a missing bucket retries immediately once the bucket is
// created instead of waiting out the backoff.
func (r *KeyReconciler) keysForBucket(ctx context.Context, obj client.Object) []reconcile.Request {
	bucket, ok := obj.(*b2v1alpha2.Bucket)
	if !ok {
		return nil
	}

	keys := &b2v1alpha2.KeyList{}
	if err := r.List(ctx, keys); err != nil {
		log.FromContext(ctx).Error(err, "Unable to list Keys while handling Bucket event", "bucket", bucket.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, k := range keys.Items {
		if k.Spec.AtProvider.BucketName == bucket.Name && (!k.Status.Reconciled || k.Status.ToRecreate) {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: k.Name, Namespace: k.Namespace},
			})
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&b2v1alpha2.Key{}).
		Owns(&corev1.Secret{}).
		Watches(&b2v1alpha2.Bucket{}, handler.EnqueueRequestsFromMapFunc(r.keysForBucket)).
		// A panic (e.g. from an unexpected provider response deep in the B2
		// library) becomes a reconcile error with backoff instead of
		// crashing the whole operator.
		WithOptions(controller.Options{RecoverPanic: ptr.To(true)}).
		Complete(r)
}
