<?php

namespace Drupal\openy_gc_auth;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Url;
use Drupal\openy_gc_auth\Event\GCUserLoginEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * User Authorizer class.
 */
class GCUserAuthorizer {

  const VIRTUAL_Y_DEFAULT_ROLE = 'virtual_y';

  /**
   * User entity storage.
   *
   * @var \Drupal\User\UserStorageInterface
   */
  protected $userStorage;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * The Messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * GCUserAuthorizer constructor.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Entity Type Manager.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   Event dispatcher.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   */
  public function __construct(EntityTypeManagerInterface $entityTypeManager, EventDispatcherInterface $event_dispatcher, MessengerInterface $messenger) {
    $this->userStorage = $entityTypeManager->getStorage('user');
    $this->eventDispatcher = $event_dispatcher;
    $this->messenger = $messenger;
  }

  /**
   * {@inheritdoc}
   */
  public function authorizeUser($name, $email, array $extra_data = []) {

    if (empty($name) || empty($email)) {
      return;
    }

    // Create drupal user if it doesn't exist and login it.
    $account = user_load_by_mail($email);
    if (!$account) {
      $user = $this->userStorage->create();
      $user->setPassword(user_password());
      $user->enforceIsNew();
      $user->setEmail($email);
      $user->setUsername($name);
      $user->addRole(self::VIRTUAL_Y_DEFAULT_ROLE);
      $user->activate();
      $result = $account = $user->save();
      if ($result) {
        $account = user_load_by_mail($email);
      }
    }
    else {
      // Activate user if it's not.
      if (!$account->isActive()) {
        $account->activate();
        $account->setPassword(user_password());
        $account->save();
      }
    }
    // List of roles to redirect user login page.
    $userRolesArray = [
      'administrator',
      'virtual_ymca_editor',
    ];
    // Redirecting user login page.
    foreach ($userRolesArray as $role) {
      if ($account->hasRole($role)) {
        $loginUrl = Url::fromRoute('user.login')->toString();
        $this->messenger->addMessage($this->t('You have to login as real user, since you are an administrator.'));
        return new RedirectResponse($loginUrl, 302);
      }
    }
    // Instantiate GC login user event.
    $event = new GCUserLoginEvent($account, $extra_data);
    // Dispatch the event.
    $this->eventDispatcher->dispatch(GCUserLoginEvent::EVENT_NAME, $event);
    user_login_finalize($account);

  }

  /**
   * {@inheritdoc}
   */
  public function createUser($name, $email, $active) {
    if (empty($name) || empty($email)) {
      return;
    }
    // Create drupal user if it doesn't exist and login it.
    $account = user_load_by_mail($email);

    if (!$account) {
      $user = $this->userStorage->create();
      $user->setPassword(user_password());
      $user->enforceIsNew();
      $user->setEmail($email);
      $user->setUsername($name);
      $user->addRole(self::VIRTUAL_Y_DEFAULT_ROLE);
      if ($active) {
        $user->activate();
      }
      $result = $account = $user->save();
      if ($result) {
        $account = user_load_by_mail($email);
      }
    }

    return $account;

  }

}
