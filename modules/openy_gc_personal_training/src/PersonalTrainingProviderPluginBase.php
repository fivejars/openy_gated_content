<?php

namespace Drupal\openy_gc_personal_training;

use Drupal\Component\Plugin\PluginBase;
use Drupal\Component\Utility\NestedArray;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Defines the base plugin for PersonalTrainingProvider classes.
 *
 * @see \Drupal\openy_gc_personal_training\PersonalTrainingProviderManager
 * @see \Drupal\openy_gc_personal_training\PersonalTrainingProviderInterface
 * @see \Drupal\openy_gc_personal_training\Annotation\PersonalTrainingProvider
 * @see plugin_api
 */
abstract class PersonalTrainingProviderPluginBase extends PluginBase implements PersonalTrainingProviderInterface, ContainerFactoryPluginInterface {

  use StringTranslationTrait;

  /**
   * The configuration factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * Current user object.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * {@inheritdoc}
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, ConfigFactoryInterface $config, EntityTypeManagerInterface $entity_type_manager, AccountProxyInterface $current_user) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    $this->configFactory = $config;
    // We use pre-saved configuration here.
    $configuration = $this->configFactory->get($this->getConfigName())->get();
    $this->setConfiguration($configuration);
    $this->entityTypeManager = $entity_type_manager;
    $this->currentUser = $current_user;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('config.factory'),
      $container->get('entity_type.manager'),
      $container->get('current_user')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getId() {
    return $this->pluginDefinition['id'];
  }

  /**
   * {@inheritdoc}
   */
  public function getLabel() {
    return $this->pluginDefinition['label'];
  }

  /**
   * {@inheritdoc}
   */
  public function getConfigName() {
    return $this->pluginDefinition['config'];
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration():array {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function getConfiguration():array {
    return $this->configuration;
  }

  /**
   * {@inheritdoc}
   */
  public function setConfiguration(array $configuration) {
    $this->configuration = NestedArray::mergeDeep(
      $this->defaultConfiguration(),
      $configuration
    );
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state):array {
    $form['admin_label'] = [
      '#type' => 'page_title',
      '#title' => $this->getLabel(),
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    // This method not required.
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    // Process the settings save if no errors occurred only.
    if (!$form_state->getErrors()) {
      // Save config in active storage.
      $configuration = $this->configFactory->getEditable($this->getConfigName());
      $configuration->setData($this->configuration);
      $configuration->save();
    }
  }

}
