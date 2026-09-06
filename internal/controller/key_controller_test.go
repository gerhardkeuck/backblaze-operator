package controller

import (
	"context"
	stderrors "errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	backblaze "github.com/mgruszkiewicz/go-backblaze"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	b2v1alpha2 "github.com/mgruszkiewicz/backblaze-operator/api/v1alpha2"
)

type secretDeleteFailingClient struct {
	client.Client
	err error
}

func (c *secretDeleteFailingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		return c.err
	}
	return c.Client.Delete(ctx, obj, opts...)
}

type secretCreateFailingClient struct {
	client.Client
	err error
}

func (c *secretCreateFailingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		return c.err
	}
	return c.Client.Create(ctx, obj, opts...)
}

func newKeyReconciler(fake *fakeB2, recorder record.EventRecorder) *KeyReconciler {
	return &KeyReconciler{
		Client:        k8sClient,
		Scheme:        scheme.Scheme,
		Backblaze:     fake,
		EventRecorder: recorder,
	}
}

func reconcileKey(r *KeyReconciler, name string) (ctrl.Result, error) {
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: "default"},
	})
}

func newKey(name, bucketName, secretName string) *b2v1alpha2.Key {
	return &b2v1alpha2.Key{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: b2v1alpha2.KeySpec{
			AtProvider: b2v1alpha2.KeySpecAtProvider{
				BucketName:   bucketName,
				Capabilities: []string{"listBuckets", "listFiles"},
			},
			WriteConnectionSecretToRef: b2v1alpha2.WriteConnectionSecretToRef{Name: secretName},
		},
	}
}

func getKey(name string) *b2v1alpha2.Key {
	key := &b2v1alpha2.Key{}
	Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, key)).To(Succeed())
	return key
}

var _ = Describe("Key controller", func() {
	ctx := context.Background()

	It("adds the finalizer on first reconcile", func() {
		key := newKey("key-finalizer", "some-bucket", "secret-key-finalizer")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(newKeyReconciler(&fakeB2{}, nil), "key-finalizer")
		Expect(err).NotTo(HaveOccurred())
		Expect(controllerutil.ContainsFinalizer(getKey("key-finalizer"), keyFinalizer)).To(BeTrue())
	})

	It("does not panic when the referenced bucket does not exist, requeues with an error and reports BucketNotFound", func() {
		// Regression test: the zero-value fake reproduces go-backblaze's
		// (nil, nil) "bucket not found" contract that used to crash the
		// operator with a nil pointer dereference.
		recorder := record.NewFakeRecorder(10)
		r := newKeyReconciler(&fakeB2{}, recorder)

		key := newKey("key-missing-bucket", "bucket-does-not-exist", "secret-key-missing-bucket")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(r, "key-missing-bucket")
		Expect(err).NotTo(HaveOccurred()) // finalizer pass

		_, err = reconcileKey(r, "key-missing-bucket")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found at provider"))

		key = getKey("key-missing-bucket")
		Expect(key.Status.Reconciled).To(BeFalse())
		cond := meta.FindStatusCondition(key.Status.Conditions, ConditionTypeReady)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(ReasonBucketNotFound))

		Eventually(recorder.Events).Should(Receive(ContainSubstring(ReasonBucketNotFound)))
	})

	It("returns an error and reports ProviderError when the bucket lookup fails", func() {
		r := newKeyReconciler(&fakeB2{bucketErr: &backblaze.B2Error{Code: "bad_auth_token", Message: "auth", Status: 401}}, nil)

		key := newKey("key-provider-error", "some-bucket", "secret-key-provider-error")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(r, "key-provider-error")
		Expect(err).NotTo(HaveOccurred())

		_, err = reconcileKey(r, "key-provider-error")
		Expect(err).To(HaveOccurred())

		cond := meta.FindStatusCondition(getKey("key-provider-error").Status.Conditions, ConditionTypeReady)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal(ReasonProviderError))
	})

	It("returns an error and reports KeyCreationFailed when the provider rejects the key", func() {
		fake := &fakeB2{
			bucket:       &backblaze.Bucket{BucketInfo: &backblaze.BucketInfo{ID: "bucket-id-1", Name: "some-bucket"}},
			createKeyErr: &backblaze.B2Error{Code: "bad_request", Message: "sensitive-test-marker", Status: 400},
		}
		r := newKeyReconciler(fake, nil)

		key := newKey("key-create-failed", "some-bucket", "secret-key-create-failed")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(r, "key-create-failed")
		Expect(err).NotTo(HaveOccurred())

		_, err = reconcileKey(r, "key-create-failed")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unable to create application key"))
		Expect(err.Error()).NotTo(ContainSubstring("sensitive-test-marker"))

		key = getKey("key-create-failed")
		Expect(key.Status.Reconciled).To(BeFalse())
		cond := meta.FindStatusCondition(key.Status.Conditions, ConditionTypeReady)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal(ReasonKeyCreationFailed))
		Expect(cond.Message).NotTo(ContainSubstring("sensitive-test-marker"))
	})

	It("creates the key and its secret when the bucket exists", func() {
		fake := &fakeB2{
			bucket: &backblaze.Bucket{BucketInfo: &backblaze.BucketInfo{ID: "bucket-id-2", Name: "existing-bucket"}},
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-happy",
				ApplicationKeyId: "app-key-id-1",
				ApplicationKey:   "app-key-secret",
			},
		}
		r := newKeyReconciler(fake, nil)

		key := newKey("key-happy", "existing-bucket", "secret-key-happy")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(r, "key-happy")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-happy")
		Expect(err).NotTo(HaveOccurred())

		key = getKey("key-happy")
		Expect(key.Status.Reconciled).To(BeTrue())
		Expect(key.Status.KeyId).To(Equal("app-key-id-1"))
		cond := meta.FindStatusCondition(key.Status.Conditions, ConditionTypeReady)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal(ReasonReconciled))

		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "secret-key-happy", Namespace: "default"}, secret)).To(Succeed())
		Expect(secret.Data).To(HaveKeyWithValue("AWS_ACCESS_KEY_ID", []byte("app-key-id-1")))
		Expect(secret.Data).To(HaveKeyWithValue("AWS_SECRET_ACCESS_KEY", []byte("app-key-secret")))
		Expect(secret.Data).To(HaveKeyWithValue("bucketName", []byte("existing-bucket")))
		Expect(metav1.IsControlledBy(secret, key)).To(BeTrue())
	})

	It("forwards the exact prefix, expiry, bucket and capabilities to the provider", func() {
		fake := &fakeB2{
			bucket: &backblaze.Bucket{BucketInfo: &backblaze.BucketInfo{ID: "bucket-id-request", Name: "request-bucket"}},
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-request",
				ApplicationKeyId: "request-key-id",
				ApplicationKey:   "test-only-secret",
			},
		}
		key := newKey("key-request", "request-bucket", "secret-key-request")
		key.Spec.AtProvider.NamePrefix = "woodpecker/"
		key.Spec.AtProvider.ValidDurationInSeconds = 3600
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(newKeyReconciler(fake, nil), "key-request")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(newKeyReconciler(fake, nil), "key-request")
		Expect(err).NotTo(HaveOccurred())

		Expect(fake.createdKeyRequests).To(HaveLen(1))
		Expect(fake.createdKeyRequests[0]).To(Equal(&backblaze.CreateKeyRequest{
			KeyName:                "key-request",
			Capabilities:           []string{"listBuckets", "listFiles"},
			ValidDurationInSeconds: 3600,
			BucketId:               "bucket-id-request",
			NamePrefix:             "woodpecker/",
		}))
	})

	It("rejects a prefix without a bucket before calling the provider", func() {
		fake := &fakeB2{}
		key := newKey("key-invalid-prefix", "", "secret-key-invalid-prefix")
		key.Spec.AtProvider.NamePrefix = "woodpecker/"

		err := newKeyReconciler(fake, nil).createOrUpdateKey(ctx, key)
		Expect(err).To(MatchError(ContainSubstring("namePrefix requires bucketName or bucketId")))
		Expect(fake.createdKeyRequests).To(BeEmpty())
	})

	It("creates an all-buckets key when no bucket is referenced", func() {
		fake := &fakeB2{
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-all-buckets",
				ApplicationKeyId: "app-key-id-2",
				ApplicationKey:   "app-key-secret-2",
			},
		}
		r := newKeyReconciler(fake, nil)

		key := newKey("key-all-buckets", "", "secret-key-all-buckets")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(r, "key-all-buckets")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-all-buckets")
		Expect(err).NotTo(HaveOccurred())

		Expect(getKey("key-all-buckets").Status.Reconciled).To(BeTrue())
		Expect(fake.createdKeyNames).To(ContainElement("key-all-buckets"))
	})

	It("rotates provider credentials and replaces only its owned Secret", func() {
		fake := &fakeB2{
			bucket: &backblaze.Bucket{BucketInfo: &backblaze.BucketInfo{ID: "bucket-id-rotate", Name: "rotate-bucket"}},
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-rotate",
				ApplicationKeyId: "old-key-id",
				ApplicationKey:   "old-test-secret",
			},
		}
		r := newKeyReconciler(fake, nil)
		key := newKey("key-rotate", "rotate-bucket", "secret-key-rotate")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		_, err := reconcileKey(r, "key-rotate")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-rotate")
		Expect(err).NotTo(HaveOccurred())

		key = getKey("key-rotate")
		key.Spec.AtProvider.NamePrefix = "keycloak/"
		key.Spec.AtProvider.ValidDurationInSeconds = 7200
		Expect(k8sClient.Update(ctx, key)).To(Succeed())
		fake.createKeyResp = &backblaze.ApplicationKeyResponse{
			KeyName:          "key-rotate",
			ApplicationKeyId: "new-key-id",
			ApplicationKey:   "new-test-secret",
		}

		_, err = reconcileKey(r, "key-rotate") // mark rotation
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-rotate") // revoke old key and delete old Secret
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-rotate") // create replacement and Secret
		Expect(err).NotTo(HaveOccurred())

		key = getKey("key-rotate")
		Expect(key.Status.Reconciled).To(BeTrue())
		Expect(key.Status.KeyId).To(Equal("new-key-id"))
		Expect(fake.deletedKeyIds).To(ContainElement("old-key-id"))
		Expect(fake.createdKeyRequests).To(HaveLen(2))
		Expect(fake.createdKeyRequests[1].NamePrefix).To(Equal("keycloak/"))
		Expect(fake.createdKeyRequests[1].ValidDurationInSeconds).To(Equal(7200))

		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "secret-key-rotate", Namespace: "default"}, secret)).To(Succeed())
		Expect(secret.Data).To(HaveKeyWithValue("AWS_ACCESS_KEY_ID", []byte("new-key-id")))
		Expect(secret.Data).To(HaveKeyWithValue("AWS_SECRET_ACCESS_KEY", []byte("new-test-secret")))
		Expect(metav1.IsControlledBy(secret, key)).To(BeTrue())
	})

	It("does not overwrite or revoke for a Secret owned by another resource", func() {
		fake := &fakeB2{
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-secret-conflict",
				ApplicationKeyId: "should-not-be-created",
				ApplicationKey:   "test-only-secret",
			},
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "shared-secret", Namespace: "default"},
			Data:       map[string][]byte{"preserved": []byte("value")},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		key := newKey("key-secret-conflict", "", "shared-secret")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		r := newKeyReconciler(fake, nil)
		_, err := reconcileKey(r, "key-secret-conflict")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-secret-conflict")
		Expect(err).To(HaveOccurred())

		Expect(fake.createdKeyRequests).To(BeEmpty())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "shared-secret", Namespace: "default"}, secret)).To(Succeed())
		Expect(secret.Data).To(HaveKeyWithValue("preserved", []byte("value")))
		cond := meta.FindStatusCondition(getKey("key-secret-conflict").Status.Conditions, ConditionTypeReady)
		Expect(cond.Reason).To(Equal(ReasonSecretConflict))
	})

	It("recovers status from an owned Secret receipt without creating a duplicate provider key", func() {
		fake := &fakeB2{}
		r := newKeyReconciler(fake, nil)
		key := newKey("key-recover-receipt", "", "secret-key-recover-receipt")
		controllerutil.AddFinalizer(key, keyFinalizer)
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		key = getKey("key-recover-receipt")
		key.Status.ToRecreate = true
		key.Status.AtProvider = key.Spec.AtProvider
		Expect(k8sClient.Status().Update(ctx, key)).To(Succeed())
		Expect(r.createKeySecret(ctx, key, &backblaze.ApplicationKeyResponse{
			KeyName:          key.Name,
			ApplicationKeyId: "receipt-key-id",
			ApplicationKey:   "receipt-test-secret",
		})).To(Succeed())

		_, err := reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		key = getKey(key.Name)
		Expect(key.Status.Reconciled).To(BeTrue())
		Expect(key.Status.KeyId).To(Equal("receipt-key-id"))
		Expect(fake.createdKeyRequests).To(BeEmpty())
	})

	It("fails closed after an uncertain provider create without a Secret receipt", func() {
		fake := &fakeB2{}
		key := newKey("key-uncertain-create", "", "secret-key-uncertain-create")
		controllerutil.AddFinalizer(key, keyFinalizer)
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		key = getKey(key.Name)
		key.Status.ToRecreate = true
		key.Status.AtProvider = key.Spec.AtProvider
		Expect(k8sClient.Status().Update(ctx, key)).To(Succeed())

		_, err := reconcileKey(newKeyReconciler(fake, nil), key.Name)
		Expect(err).To(HaveOccurred())
		Expect(fake.createdKeyRequests).To(BeEmpty())
		cond := meta.FindStatusCondition(getKey(key.Name).Status.Conditions, ConditionTypeReady)
		Expect(cond.Reason).To(Equal(ReasonKeyCreationUncertain))
	})

	It("revokes a newly created provider key when Secret publication fails", func() {
		fake := &fakeB2{
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-secret-create-fails",
				ApplicationKeyId: "unpublished-key-id",
				ApplicationKey:   "test-only-secret",
			},
		}
		r := newKeyReconciler(fake, nil)
		key := newKey("key-secret-create-fails", "", "secret-key-create-fails")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		_, err := reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		r.Client = &secretCreateFailingClient{Client: k8sClient, err: stderrors.New("injected Secret create failure")}

		_, err = reconcileKey(r, key.Name)
		Expect(err).To(HaveOccurred())
		Expect(fake.deletedKeyIds).To(ContainElement("unpublished-key-id"))
		key = getKey(key.Name)
		Expect(key.Status.Reconciled).To(BeFalse())
		Expect(key.Status.ToRecreate).To(BeFalse())
		cond := meta.FindStatusCondition(key.Status.Conditions, ConditionTypeReady)
		Expect(cond.Reason).To(Equal(ReasonSecretWriteFailed))
	})

	It("repairs a missing owned Secret through controlled rotation", func() {
		fake := &fakeB2{
			createKeyResp: &backblaze.ApplicationKeyResponse{KeyName: "key-missing-secret", ApplicationKeyId: "missing-old-id", ApplicationKey: "old-test-secret"},
		}
		r := newKeyReconciler(fake, nil)
		key := newKey("key-missing-secret", "", "secret-key-missing-secret")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		_, err := reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "secret-key-missing-secret", Namespace: "default"}, secret)).To(Succeed())
		Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

		_, err = reconcileKey(r, key.Name) // detect missing Secret
		Expect(err).NotTo(HaveOccurred())
		cond := meta.FindStatusCondition(getKey(key.Name).Status.Conditions, ConditionTypeReady)
		Expect(cond.Reason).To(Equal(ReasonSecretMissing))
		fake.createKeyResp = &backblaze.ApplicationKeyResponse{KeyName: key.Name, ApplicationKeyId: "missing-new-id", ApplicationKey: "new-test-secret"}
		_, err = reconcileKey(r, key.Name) // revoke old key
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, key.Name) // create replacement
		Expect(err).NotTo(HaveOccurred())

		Expect(fake.deletedKeyIds).To(ContainElement("missing-old-id"))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "secret-key-missing-secret", Namespace: "default"}, secret)).To(Succeed())
		Expect(secret.Data).To(HaveKeyWithValue("AWS_ACCESS_KEY_ID", []byte("missing-new-id")))
	})

	It("maps Bucket events to pending Keys referencing that bucket", func() {
		r := newKeyReconciler(&fakeB2{}, nil)

		waiting := newKey("key-watch-waiting", "watched-bucket", "secret-key-watch-waiting")
		Expect(k8sClient.Create(ctx, waiting)).To(Succeed())

		other := newKey("key-watch-other", "some-other-bucket", "secret-key-watch-other")
		Expect(k8sClient.Create(ctx, other)).To(Succeed())

		reconciled := newKey("key-watch-done", "watched-bucket", "secret-key-watch-done")
		Expect(k8sClient.Create(ctx, reconciled)).To(Succeed())
		reconciled = getKey("key-watch-done")
		reconciled.Status.Reconciled = true
		Expect(k8sClient.Status().Update(ctx, reconciled)).To(Succeed())

		requests := r.keysForBucket(ctx, &b2v1alpha2.Bucket{
			ObjectMeta: metav1.ObjectMeta{Name: "watched-bucket", Namespace: "default"},
		})
		Expect(requests).To(ConsistOf(ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "key-watch-waiting", Namespace: "default"},
		}))
	})

	It("deletes the application key and secret when the Key is deleted", func() {
		fake := &fakeB2{
			bucket: &backblaze.Bucket{BucketInfo: &backblaze.BucketInfo{ID: "bucket-id-3", Name: "existing-bucket"}},
			createKeyResp: &backblaze.ApplicationKeyResponse{
				KeyName:          "key-delete",
				ApplicationKeyId: "app-key-id-3",
				ApplicationKey:   "app-key-secret-3",
			},
		}
		r := newKeyReconciler(fake, nil)

		key := newKey("key-delete", "existing-bucket", "secret-key-delete")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		_, err := reconcileKey(r, "key-delete")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, "key-delete")
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Delete(ctx, getKey("key-delete"))).To(Succeed())
		_, err = reconcileKey(r, "key-delete")
		Expect(err).NotTo(HaveOccurred())

		Expect(fake.deletedKeyIds).To(ContainElement("app-key-id-3"))
		err = k8sClient.Get(ctx, types.NamespacedName{Name: "key-delete", Namespace: "default"}, &b2v1alpha2.Key{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("expected Key to be gone, got: %v", err))
		err = k8sClient.Get(ctx, types.NamespacedName{Name: "secret-key-delete", Namespace: "default"}, &corev1.Secret{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("keeps the finalizer when credential Secret deletion fails", func() {
		fake := &fakeB2{
			createKeyResp: &backblaze.ApplicationKeyResponse{KeyName: "key-secret-delete-fails", ApplicationKeyId: "delete-secret-id", ApplicationKey: "test-only-secret"},
		}
		r := newKeyReconciler(fake, nil)
		key := newKey("key-secret-delete-fails", "", "secret-key-delete-fails")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		_, err := reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Delete(ctx, getKey(key.Name))).To(Succeed())

		r.Client = &secretDeleteFailingClient{Client: k8sClient, err: stderrors.New("injected Secret delete failure")}
		_, err = reconcileKey(r, key.Name)
		Expect(err).To(HaveOccurred())
		Expect(controllerutil.ContainsFinalizer(getKey(key.Name), keyFinalizer)).To(BeTrue())
		Expect(fake.deleteKeyCalls).To(BeEmpty())
	})

	It("keeps the finalizer on provider deletion failure and treats confirmed NotFound as success", func() {
		fake := &fakeB2{
			createKeyResp: &backblaze.ApplicationKeyResponse{KeyName: "key-provider-delete-fails", ApplicationKeyId: "delete-provider-id", ApplicationKey: "test-only-secret"},
		}
		r := newKeyReconciler(fake, nil)
		key := newKey("key-provider-delete-fails", "", "secret-key-provider-delete-fails")
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		_, err := reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Delete(ctx, getKey(key.Name))).To(Succeed())

		fake.deleteKeyErr = &backblaze.B2Error{Code: "service_unavailable", Message: "contains-sensitive-provider-detail", Status: 503}
		_, err = reconcileKey(r, key.Name)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("contains-sensitive-provider-detail"))
		Expect(controllerutil.ContainsFinalizer(getKey(key.Name), keyFinalizer)).To(BeTrue())

		fake.deleteKeyErr = &backblaze.B2Error{Code: "not_found", Message: "contains-sensitive-provider-detail", Status: 404}
		_, err = reconcileKey(r, key.Name)
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.Get(ctx, types.NamespacedName{Name: key.Name, Namespace: "default"}, &b2v1alpha2.Key{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})
})
