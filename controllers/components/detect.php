<?php

Configure::load('Intrusion.settings');
class DetectComponent extends Object {

  public $components = array('Session', 'Auth', 'Email');

  public function initialize(&$controller) {
    $this->Intrusion = ClassRegistry::init('Intrusion');
  }

  public function startup (&$controller) {
    self::__recordFailure(&$controller);
  }

  public function checkForPenalty () {
    $this->IntrusionPenalty = ClassRegistry::init('IntrusionPenalty');
    $user = $this->IntrusionPenalty->find('first', array(
        'conditions' => array(
          'IntrusionPenalty.ipaddress' => $_SERVER['REMOTE_ADDR'],
          'IntrusionPenalty.expires >' => mktime()
        ),
        'order' => 'IntrusionPenalty.id DESC'
      ));
    if (!empty($user)) {
      $time = date('m-d-Y g:i a',$user['IntrusionPenalty']['expires']);
      $this->Session->setFlash('Sorry you have exceeded max login attempts. Please try again at '. $time, 'default', array('class' => 'error'));
      return true;
    }
    else {
      return false;
    }
  }

  private function __recordFailure(&$controller) {
    if ($controller->action == 'login' && isset($controller->data)) {
      if ($this->Session->read('Message.auth.message') == $this->Auth->loginError) {
        $this->Intrusion->save(array('ipaddress' => $_SERVER['REMOTE_ADDR'], 'created' => mktime()));
        self::__blockUser();
      }
    }
  }

  private function __blockUser() {
    $count = $this->Intrusion->find('count', array(
        'conditions' => array(
          'Intrusion.ipaddress' => $_SERVER['REMOTE_ADDR'], 
          'Intrusion.created >' => mktime() - Configure::read('Intrusion.look_back')
        )
      ));

    if ($count >= Configure::read('Intrusion.max_attempts')) {
      $this->IntrusionPenalty->create();
      $this->IntrusionPenalty->save(array(
          'ipaddress' => $_SERVER['REMOTE_ADDR'],
          'expires' => mktime() + Configure::read('Intrusion.max_penalty')
        ));
      self::__notify($count);
    }
  }

  private function __notify($count) {
    
    $this->Email->to        = Configure::read('Intrusion.notify');
    $this->Email->subject   = 'A user exceed max login attempts';

    // structure the email message
    $msg  = '-----------------------------------------------------------' . "\n";
    $msg .= '                     SECURITY NOTICE ' . "\n";               
    $msg .= '-----------------------------------------------------------' . "\n";
    $msg .= '' . "\n";
    $msg .= 'IP Address:       '. $_SERVER['REMOTE_ADDR'] . "\n";
    $msg .= 'Total Attempts:   '. $count . "\n";
    $msg .= '' . "\n";

    $this->Email->delivery = 'debug';
    $this->Email->send($msg);
  }

}